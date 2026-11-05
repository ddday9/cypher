// Package server implements the cypher server.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/ddday9/cypher/internal/router"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/acme"
)

const (
	handshakeTimeout = 15 * time.Second
	authTimeout      = 30 * time.Second
	requestTimeout   = 30 * time.Second
	dialTimeout      = 10 * time.Second

	// A client with open streams sends keepalives at most 40 s apart;
	// nothing for deadClientTimeout means it is gone. An idle session (no
	// streams) of a current client is silent; it is dropped after
	// idleSessionTimeout (clients close idle tunnels after 1–3 min anyway).
	deadClientTimeout  = 2 * time.Minute
	idleSessionTimeout = 5 * time.Minute
)

// Server accepts cypher clients and serves a fallback website to everyone else.
type Server struct {
	listen       string
	tlsConfig    *tls.Config
	auth         *protocol.Authenticator
	fallback     *fallback
	allowPrivate bool
	resolver     *net.Resolver

	router atomic.Pointer[router.Router]

	// upstream is where client traffic leaves the server.
	upstream Upstream

	// exit is the upstream server of a relay (nil: traffic goes to the
	// internet). e2eKey lets this server be the exit of end-to-end
	// encrypted streams (nil: unavailable).
	exit   *client.Cypher
	e2eKey *protocol.E2EKey
	caps   uint16

	sessMu   sync.Mutex
	sessions map[protocol.Key]map[io.Closer]struct{}

	segMu sync.Mutex
	segs  map[[16]byte]*segEntry // anti-freeze sessions by id
}

// New builds a server from its config section. base resolves relative paths.
func New(cfg *config.ServerConfig, resolve func(string) string) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("server: no users configured")
	}
	users, err := parseUsers(cfg.Users)
	if err != nil {
		return nil, err
	}
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	nextProtos := []string{"h2", "http/1.1"}
	switch {
	case cfg.ACME != nil:
		cm, err := newACME(cfg.ACME, resolve)
		if err != nil {
			return nil, err
		}
		getCert = cm.get
		// Lets the CA validate the domain on this port (TLS-ALPN-01).
		nextProtos = append(nextProtos, acme.ALPNProto)
	case cfg.CertFile != "" && cfg.KeyFile != "":
		certs, err := newCertReloader(resolve(cfg.CertFile), resolve(cfg.KeyFile))
		if err != nil {
			return nil, err
		}
		getCert = certs.get
	default:
		return nil, errors.New("server: set acme.domain, or certFile and keyFile")
	}
	fbCfg := cfg.Fallback
	if fbCfg.Dir != "" {
		fbCfg.Dir = resolve(fbCfg.Dir)
	}
	fb, err := newFallback(fbCfg)
	if err != nil {
		return nil, err
	}
	listen := cfg.Listen
	if listen == "" {
		listen = ":443"
	}
	s := &Server{
		listen: listen,
		tlsConfig: &tls.Config{
			GetCertificate: getCert,
			NextProtos:     nextProtos,
			MinVersion:     tls.VersionTLS12,
		},
		auth:         protocol.NewAuthenticator(users),
		fallback:     fb,
		allowPrivate: cfg.AllowPrivate,
		resolver:     net.DefaultResolver,
		sessions:     map[protocol.Key]map[io.Closer]struct{}{},
		segs:         map[[16]byte]*segEntry{},
		upstream:     directUpstream{},
		caps:         serverCaps,
	}
	if cfg.Upstream != nil {
		exit, err := newExit(cfg.Upstream, resolve)
		if err != nil {
			return nil, err
		}
		s.exit = exit
		s.caps |= protocol.CapRelay
	}
	keyFile := cfg.E2EKeyFile
	if keyFile == "" {
		keyFile = "e2e.key"
	}
	if k, err := LoadOrCreateE2EKey(resolve(keyFile)); err != nil {
		slog.Warn("end-to-end encryption through relays is off: no key", "file", resolve(keyFile), "err", err)
	} else {
		s.e2eKey = &k
		s.caps |= protocol.CapE2E
	}
	return s, nil
}

// Upstream dials the internet for the "direct" route (replaceable in tests).
// The "exit" route of a relay goes through Server.exit instead.
type Upstream interface {
	DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

type directUpstream struct{}

func (directUpstream) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr.String())
}

// serverCaps are the protocol v2 features this server offers.
const serverCaps = protocol.CapPing | protocol.CapSegmented | protocol.CapQuietIdle

func parseUsers(list []config.UserConfig) ([]protocol.User, error) {
	var users []protocol.User
	seen := map[protocol.Key]bool{}
	for i, u := range list {
		k, err := protocol.ParseKey(u.Key)
		if err != nil {
			return nil, fmt.Errorf("server.users[%d]: %w", i, err)
		}
		if seen[k] {
			return nil, fmt.Errorf("server.users[%d]: duplicate key", i)
		}
		seen[k] = true
		name := u.Name
		if name == "" {
			name = fmt.Sprintf("user%d", i+1)
		}
		users = append(users, protocol.User{Name: name, Key: k})
	}
	return users, nil
}

// SetUsers applies a new user list without a restart. Sessions of users
// whose key is no longer listed are closed at once.
func (s *Server) SetUsers(list []config.UserConfig) error {
	users, err := parseUsers(list)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return errors.New("no users configured")
	}
	s.auth.SetUsers(users)
	keep := map[protocol.Key]bool{}
	for _, u := range users {
		keep[u.Key] = true
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for k, set := range s.sessions {
		if keep[k] {
			continue
		}
		for sess := range set {
			sess.Close()
		}
		delete(s.sessions, k)
		slog.Info("revoked user disconnected", "sessions", len(set))
	}
	return nil
}

func (s *Server) track(k protocol.Key, sess io.Closer) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	// The user may have been revoked between authentication and here.
	if !s.auth.HasKey(k) {
		sess.Close()
		return
	}
	if s.sessions[k] == nil {
		s.sessions[k] = map[io.Closer]struct{}{}
	}
	s.sessions[k][sess] = struct{}{}
}

func (s *Server) untrack(k protocol.Key, sess io.Closer) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	delete(s.sessions[k], sess)
	if len(s.sessions[k]) == 0 {
		delete(s.sessions, k)
	}
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	slog.Info("server listening", "addr", ln.Addr().String())
	return s.Serve(ctx, ln)
}

// Serve accepts connections from ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
		s.fallback.close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	tc := tls.Server(raw, s.tlsConfig)
	tc.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tc.Handshake(); err != nil {
		slog.Debug("tls handshake failed", "remote", raw.RemoteAddr().String(), "err", err)
		raw.Close()
		return
	}
	if tc.ConnectionState().NegotiatedProtocol == acme.ALPNProto {
		tc.Close() // an ACME validation handshake; nothing follows
		return
	}
	tc.SetDeadline(time.Now().Add(authTimeout))
	res, prefix, err := s.auth.ReadAuthExt(tc)
	if errors.Is(err, protocol.ErrNotAuthenticated) {
		slog.Debug("not a client, serving fallback", "remote", raw.RemoteAddr().String())
		s.fallback.serve(tc, prefix)
		return
	}
	if err != nil {
		tc.Close()
		return
	}
	tc.SetDeadline(time.Time{})
	user := res.User
	rc := protocol.NewRecordConn(tc, nil)
	if res.Ext != nil && res.Ext.Flags&protocol.FlagSegmented != 0 {
		s.handleSegmented(rc, user, res.Ext, raw.RemoteAddr().String())
		return
	}
	version := 1
	if res.Ext != nil && res.Ext.Flags&protocol.FlagV2 != 0 {
		// Protocol v2: answer pings and announce what this server supports.
		version = 2
		rc.SetControlHandler(func(typ byte, body []byte) {
			if typ == protocol.CtlPing {
				rc.WriteControl(protocol.CtlPong, body)
			}
		})
		if err := rc.WriteControl(protocol.CtlHello, protocol.Hello(s.caps)); err != nil {
			tc.Close()
			return
		}
	}
	slog.Info("client connected", "user", user.Name, "remote", raw.RemoteAddr().String(), "protocol", version)

	sess, err := smux.Server(rc, protocol.MuxConfig())
	if err != nil {
		tc.Close()
		return
	}
	defer sess.Close()
	// Clients older than FlagQuietIdle drop a session after 60 s without
	// data, so they get keepalives even while idle.
	quiet := res.Ext != nil && res.Ext.Flags&protocol.FlagQuietIdle != 0
	go protocol.KeepAlive(sess, rc.WriteKeepAlive, func() bool { return !quiet }, rc.LastRead,
		deadClientTimeout, idleSessionTimeout)
	s.track(user.Key, sess)
	defer s.untrack(user.Key, sess)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			slog.Debug("session closed", "user", user.Name, "err", err)
			return
		}
		go s.handleStream(st, user)
	}
}

func (s *Server) handleStream(st *smux.Stream, user *protocol.User) {
	defer st.Close()
	st.SetDeadline(time.Now().Add(requestTimeout))
	req, err := protocol.ReadRequest(st)
	if err != nil {
		slog.Debug("bad request", "user", user.Name, "err", err)
		return
	}
	switch {
	case req.Cmd == protocol.CmdE2E && s.exit != nil:
		s.forwardE2E(st, user) // destination hidden from us: the exit decides
	case req.Cmd == protocol.CmdE2E:
		s.handleE2E(st, user)
	case req.Cmd&protocol.CmdFlagE2E != 0 && s.exit != nil:
		s.handleRelayE2E(st, user, req)
	case req.Cmd == protocol.CmdTCP || req.Cmd == protocol.CmdUDP:
		s.serve(st, user, req, s.route(user.Name, req.Dest), plainAnswer(st))
	default:
		st.Write([]byte{protocol.StatusFailure})
	}
}

// answerFunc sends the request's status and returns the connection the data
// flows on (the stream itself, or its end-to-end encrypted layer).
type answerFunc func(status byte) (net.Conn, error)

func plainAnswer(st net.Conn) answerFunc {
	return func(status byte) (net.Conn, error) {
		if _, err := st.Write([]byte{status}); err != nil {
			return nil, err
		}
		if status != protocol.StatusOK {
			return nil, protocol.StatusError(status)
		}
		return st, nil
	}
}

// serve carries out a TCP or UDP request along route.
func (s *Server) serve(st net.Conn, user *protocol.User, req protocol.Request, route string, answer answerFunc) {
	if req.Cmd == protocol.CmdUDP {
		if route == routeBlock {
			answer(protocol.StatusNotAllowed)
			return
		}
		conn, err := answer(protocol.StatusOK)
		if err != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		s.handleUDP(conn, user)
		return
	}
	var target net.Conn
	var status byte
	switch route {
	case routeBlock:
		status = protocol.StatusNotAllowed
		slog.Debug("blocked by server rules", "user", user.Name, "dest", req.Dest.String())
	case routeExit:
		ctx, cancel := context.WithTimeout(context.Background(), 2*dialTimeout)
		target, status = s.dialExit(ctx, req.Dest)
		cancel()
	default:
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		target, status = s.dial(ctx, req.Dest)
		cancel()
	}
	conn, err := answer(status)
	if err != nil || status != protocol.StatusOK {
		if target != nil {
			target.Close()
		}
		slog.Debug("connect failed", "user", user.Name, "dest", req.Dest.String(), "route", route, "status", status)
		return
	}
	conn.SetDeadline(time.Time{})
	slog.Debug("connect", "user", user.Name, "dest", req.Dest.String(), "route", route)
	netx.Relay(conn, target)
}

// dial resolves the destination itself so that private-address filtering
// cannot be bypassed with a domain that points at 127.0.0.1.
func (s *Server) dial(ctx context.Context, dest netx.Destination) (net.Conn, byte) {
	var addrs []netip.Addr
	if a, ok := dest.Addr(); ok {
		addrs = []netip.Addr{a}
	} else {
		res, err := s.resolver.LookupNetIP(ctx, "ip", dest.Host)
		if err != nil || len(res) == 0 {
			return nil, protocol.StatusUnreachable
		}
		addrs = res
	}
	status := protocol.StatusNotAllowed
	for _, a := range addrs {
		a = a.Unmap()
		if !s.allowPrivate && isPrivate(a) {
			continue
		}
		c, err := s.upstream.DialTCP(ctx, netip.AddrPortFrom(a, dest.Port))
		if err == nil {
			return c, protocol.StatusOK
		}
		status = dialStatus(err)
	}
	return nil, status
}

func dialStatus(err error) byte {
	var oe *net.OpError
	if errors.As(err, &oe) && errors.Is(oe.Err, os.ErrDeadlineExceeded) {
		return protocol.StatusUnreachable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return protocol.StatusUnreachable
	}
	if isConnRefused(err) {
		return protocol.StatusRefused
	}
	return protocol.StatusFailure
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPrivate(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() ||
		a.IsInterfaceLocalMulticast() || cgnat.Contains(a)
}

// certReloader re-reads the certificate when the files change, so a renewal
// by certbot is picked up without a restart.
type certReloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	modTime   time.Time
	lastCheck time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.cert, r.modTime = &cert, st.ModTime()
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastCheck) > time.Minute {
		r.lastCheck = time.Now()
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.modTime) {
			if err := r.load(); err != nil {
				slog.Warn("certificate reload failed, keeping the old one", "err", err)
			} else {
				slog.Info("certificate reloaded")
			}
		}
	}
	return r.cert, nil
}

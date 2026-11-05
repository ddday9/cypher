// Package server implements the cypher server.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/xtaci/smux"
)

const (
	handshakeTimeout = 15 * time.Second
	authTimeout      = 30 * time.Second
	requestTimeout   = 30 * time.Second
	dialTimeout      = 10 * time.Second
)

// Server accepts cypher clients and serves a fallback website to everyone else.
type Server struct {
	listen       string
	tlsConfig    *tls.Config
	auth         *protocol.Authenticator
	fallback     *fallback
	allowPrivate bool
	resolver     *net.Resolver
}

// New builds a server from its config section. base resolves relative paths.
func New(cfg *config.ServerConfig, resolve func(string) string) (*Server, error) {
	if len(cfg.Users) == 0 {
		return nil, errors.New("server: no users configured")
	}
	var users []protocol.User
	for i, u := range cfg.Users {
		k, err := protocol.ParseKey(u.Key)
		if err != nil {
			return nil, fmt.Errorf("server.users[%d]: %w", i, err)
		}
		name := u.Name
		if name == "" {
			name = fmt.Sprintf("user%d", i+1)
		}
		users = append(users, protocol.User{Name: name, Key: k})
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("server: certFile and keyFile are required")
	}
	certs, err := newCertReloader(resolve(cfg.CertFile), resolve(cfg.KeyFile))
	if err != nil {
		return nil, err
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
	return &Server{
		listen: listen,
		tlsConfig: &tls.Config{
			GetCertificate: certs.get,
			NextProtos:     []string{"h2", "http/1.1"},
			MinVersion:     tls.VersionTLS12,
		},
		auth:         protocol.NewAuthenticator(users),
		fallback:     fb,
		allowPrivate: cfg.AllowPrivate,
		resolver:     net.DefaultResolver,
	}, nil
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
	tc.SetDeadline(time.Now().Add(authTimeout))
	user, prefix, err := s.auth.ReadAuth(tc)
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
	slog.Info("client connected", "user", user.Name, "remote", raw.RemoteAddr().String())

	sess, err := smux.Server(protocol.NewRecordConn(tc, nil), protocol.MuxConfig())
	if err != nil {
		tc.Close()
		return
	}
	defer sess.Close()
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
	if req.Cmd != protocol.CmdTCP {
		st.Write([]byte{protocol.StatusFailure})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	target, status := s.dial(ctx, req.Dest)
	cancel()
	if _, err := st.Write([]byte{status}); err != nil || status != protocol.StatusOK {
		if target != nil {
			target.Close()
		}
		slog.Debug("connect failed", "user", user.Name, "dest", req.Dest.String(), "status", status)
		return
	}
	st.SetDeadline(time.Time{})
	slog.Debug("connect", "user", user.Name, "dest", req.Dest.String())
	netx.Relay(st, target)
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
	var d net.Dialer
	status := protocol.StatusNotAllowed
	for _, a := range addrs {
		a = a.Unmap()
		if !s.allowPrivate && isPrivate(a) {
			continue
		}
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, dest.Port).String())
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

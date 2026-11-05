// Package client implements outbounds: cypher (the tunnel), direct and block.
package client

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

// Outbound is a named way of reaching a destination.
type Outbound interface {
	netx.Dialer
	// ListenPacket opens a UDP association; dest is the first destination
	// (used for logging), every packet carries its own address.
	ListenPacket(ctx context.Context, dest netx.Destination) (netx.PacketConn, error)
	Tag() string
	Close() error
}

// New builds an outbound from config. resolve turns relative paths into usable ones.
func New(cfg config.OutboundConfig, resolve func(string) string) (Outbound, error) {
	switch strings.ToLower(cfg.Type) {
	case "direct", "freedom":
		return &Direct{tag: cfg.Tag}, nil
	case "block", "blackhole":
		return &Block{tag: cfg.Tag}, nil
	case "cypher":
		return newCypher(cfg, resolve)
	default:
		return nil, fmt.Errorf("unknown outbound type %q", cfg.Type)
	}
}

// Direct connects straight to the destination.
type Direct struct{ tag string }

func (d *Direct) Tag() string  { return d.tag }
func (d *Direct) Close() error { return nil }
func (d *Direct) Dial(ctx context.Context, dest netx.Destination) (net.Conn, error) {
	addr := dest.String()
	if orig, ok := netx.OriginalFrom(ctx); ok && orig.Port() == dest.Port {
		addr = orig.String() // TUN: the domain was only sniffed for routing
	}
	conn, err := netx.NewDialer(10*time.Second).DialContext(ctx, "tcp", addr)
	if err != nil || netx.BoundInterface() == nil {
		return conn, err
	}
	port := netx.AddrPortOf(conn.LocalAddr()).Port()
	netx.AddOwnPort("tcp", port)
	return &ownConn{Conn: conn, port: port}, nil
}

// ownConn unregisters a direct TCP connection's port when it closes.
type ownConn struct {
	net.Conn
	port uint16
	once sync.Once
}

func (c *ownConn) Close() error {
	c.once.Do(func() { netx.RemoveOwnPort("tcp", c.port) })
	return c.Conn.Close()
}

// Block refuses every connection.
type Block struct{ tag string }

// ErrBlocked is returned by the block outbound.
var ErrBlocked = errors.New("blocked by routing rules")

func (b *Block) Tag() string  { return b.tag }
func (b *Block) Close() error { return nil }
func (b *Block) Dial(context.Context, netx.Destination) (net.Conn, error) {
	return nil, ErrBlocked
}

func (b *Block) ListenPacket(context.Context, netx.Destination) (netx.PacketConn, error) {
	return nil, ErrBlocked
}

// deadServerTimeout: a tunnel with open streams that has heard nothing from
// the server for this long is closed (servers send keepalives at most 40 s
// apart while streams are open).
const deadServerTimeout = 2 * time.Minute

var fingerprints = map[string]utls.ClientHelloID{
	"":        utls.HelloFirefox_Auto, // default
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	// "random" picks one of the real browser profiles in randomPool, derived
	// from the key and the server: different users of one server look like
	// different browsers, but each one keeps its fingerprint across
	// connections and restarts. (A client whose fingerprint changes while
	// it is being throttled was reported to get a 600 s ban; uTLS's fully
	// randomized hello looks like no browser and sometimes fails.)
	"random": {},
}

// randomPool holds the profiles reported (2026) to pass the TSPU's
// ClientHello scoring even towards "suspicious" hosting ranges, where
// Chrome, Safari and iOS hellos were held.
var randomPool = []utls.ClientHelloID{
	utls.HelloFirefox_Auto, utls.HelloEdge_Auto, utls.HelloAndroid_11_OkHttp,
}

// Cypher tunnels connections to a cypher server, multiplexing streams over
// a single TLS connection.
type Cypher struct {
	tag        string
	server     string
	serverName string
	key        protocol.Key
	hello      utls.ClientHelloID
	roots      *x509.CertPool
	insecure   bool

	pool   *pool
	pinned atomic.Pointer[string] // resolved server address, see PinServer
	e2e    *e2eConfig
	// eagerHello: learn the server's capabilities right after connecting
	// (set for a relay's upstream, see NeedCaps).
	eagerHello bool
	seg        segState
}

// PinServer resolves the server address once and uses the IP from then on.
// TUN mode calls it before taking over routing, so that connecting to the
// server never depends on DNS that itself goes through the tunnel.
func (c *Cypher) PinServer(ctx context.Context) error {
	host, port, _ := net.SplitHostPort(c.server)
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve server %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("resolve server %s: no addresses", host)
	}
	best := addrs[0]
	for _, a := range addrs { // prefer IPv4: IPv6 is often missing on the client side
		if a.Unmap().Is4() {
			best = a
			break
		}
	}
	addr := net.JoinHostPort(best.Unmap().String(), port)
	c.pinned.Store(&addr)
	slog.Info("server address pinned", "outbound", c.tag, "server", c.server, "ip", addr)
	return nil
}

// ServerIPs returns the pinned server address, if any.
func (c *Cypher) ServerIPs() []netip.Addr {
	if p := c.pinned.Load(); p != nil {
		if ap, err := netip.ParseAddrPort(*p); err == nil {
			return []netip.Addr{ap.Addr()}
		}
	}
	host, _, _ := net.SplitHostPort(c.server)
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}
	}
	return nil
}

func newCypher(cfg config.OutboundConfig, resolve func(string) string) (*Cypher, error) {
	if cfg.Server == "" {
		return nil, errors.New("cypher outbound: server is required")
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("cypher outbound: server must be host:port: %w", err)
	}
	key, err := protocol.ParseKey(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("cypher outbound: %w", err)
	}
	hello, ok := fingerprints[strings.ToLower(cfg.Fingerprint)]
	if !ok {
		return nil, fmt.Errorf("cypher outbound: unknown fingerprint %q", cfg.Fingerprint)
	}
	if hello == (utls.ClientHelloID{}) {
		h := sha256.Sum256(append([]byte(cfg.Server+"\x00"+cfg.ServerName+"\x00"), key[:]...))
		hello = randomPool[int(h[0])%len(randomPool)]
		slog.Info("fingerprint chosen", "outbound", cfg.Tag, "fingerprint", hello.Client)
	}
	var e2e *e2eConfig
	// End to end only with the user's exit key. An exit's own links carry
	// its public key (epk) too, for setting up relays; alone it means
	// nothing to a client connecting directly.
	if cfg.ExitKey != "" {
		ek, err := protocol.ParseKey(cfg.ExitKey)
		if err != nil {
			return nil, fmt.Errorf("cypher outbound: exitKey: %w", err)
		}
		pub, err := protocol.ParseE2EPublic(cfg.ExitPublicKey)
		if err != nil {
			return nil, fmt.Errorf("cypher outbound: exitPublicKey: %w", err)
		}
		e2e = &e2eConfig{pub: pub, key: ek, hide: cfg.HideDestinations}
	}
	c := &Cypher{
		e2e:        e2e,
		tag:        cfg.Tag,
		server:     cfg.Server,
		serverName: cfg.ServerName,
		key:        key,
		hello:      hello,
		insecure:   cfg.Insecure,
	}
	if c.serverName == "" {
		c.serverName = host
	}
	if cfg.CA != "" {
		pem, err := os.ReadFile(resolve(cfg.CA))
		if err != nil {
			return nil, fmt.Errorf("cypher outbound: ca: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("cypher outbound: ca: no certificates found")
		}
		c.roots = pool
	}
	rot, err := parseRotation(cfg.Rotation)
	if err != nil {
		return nil, fmt.Errorf("cypher outbound: %w", err)
	}
	if c.seg.mode, err = parseAntiFreeze(cfg.AntiFreeze); err != nil {
		return nil, fmt.Errorf("cypher outbound: %w", err)
	}
	c.seg.rate = carrierBurst
	if cfg.AntiFreezeRate > 0 {
		c.seg.rate = cfg.AntiFreezeRate
	}
	size := cfg.Connections
	if cfg.SingleConnection {
		size = 1
		if c.seg.mode == antiFreezeOn {
			slog.Warn("cypher outbound: antiFreeze is off with singleConnection", "tag", c.tag)
		}
		c.seg.mode = antiFreezeOff // anti-freeze needs a new connection every few KB
	}
	c.pool = newPool(c.tag, size, rot, c.connect)
	c.pool.single = cfg.SingleConnection
	c.pool.onFreeze = c.onFreeze
	if c.insecure {
		slog.Warn("cypher outbound: certificate verification is disabled (insecure: true) — use only for testing", "tag", c.tag)
	}
	return c, nil
}

func (c *Cypher) Tag() string { return c.tag }

func (c *Cypher) helloID() utls.ClientHelloID { return c.hello }

func (c *Cypher) Close() error {
	c.pool.close()
	return nil
}

func (c *Cypher) connect(ctx context.Context) (*link, error) {
	if c.seg.wantSegmented() {
		return c.connectSegmented(ctx)
	}
	return c.connectPlain(ctx)
}

// connectPlain opens a tunnel that carries smux directly (one TLS
// connection per tunnel).
func (c *Cypher) connectPlain(ctx context.Context) (*link, error) {
	uc, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	ext := &protocol.Ext{Flags: protocol.FlagV2 | protocol.FlagQuietIdle}
	rc := protocol.NewRecordConn(uc, protocol.BuildAuthExt(c.key, time.Now(), ext))
	l := newLink()
	l.rc = rc
	rc.SetControlHandler(func(typ byte, body []byte) {
		switch typ {
		case protocol.CtlHello:
			if caps, ok := protocol.ParseHello(body); ok {
				l.caps.Store(uint32(caps))
				if caps&protocol.CapSegmented != 0 {
					c.seg.supported.Store(1)
				}
			}
			l.helloDone()
		case protocol.CtlPong:
			if len(body) == 4 {
				l.pong.Store(binary.BigEndian.Uint32(body))
			}
		}
	})
	sess, err := smux.Client(rc, protocol.MuxConfig())
	if err != nil {
		uc.Close()
		return nil, err
	}
	l.sess = sess
	if c.e2e != nil || c.eagerHello {
		// The server speaks only after our auth header, which otherwise
		// goes out with the first stream. Streams that depend on the
		// server's capabilities need its HELLO first, so send the header
		// now in an empty record (which older servers skip).
		if _, err := rc.Write(nil); err != nil {
			sess.Close()
			return nil, err
		}
	}
	// Servers without CapQuietIdle (older versions) drop a session after
	// 60 s without data, so they get keepalives even while it is idle. A
	// server sends keepalives while streams are open; nothing at all for
	// deadServerTimeout means the connection is dead.
	go protocol.KeepAlive(sess, rc.WriteKeepAlive,
		func() bool { return l.caps.Load()&uint32(protocol.CapQuietIdle) == 0 },
		rc.LastRead, deadServerTimeout, 0)
	slog.Debug("connected to server", "outbound", c.tag, "server", c.server)
	return l, nil
}

// e2eConfig is set when streams to the exit behind a relay are encrypted
// end to end.
type e2eConfig struct {
	pub  []byte
	key  protocol.Key
	hide bool
}

// errE2E marks an end-to-end handshake failure: the tunnel is fine, so the
// request is not retried on another one.
type errE2E struct{ err error }

func (e errE2E) Error() string { return "end-to-end encryption with the exit: " + e.err.Error() }
func (e errE2E) Unwrap() error { return e.err }

// ErrNoE2E is returned by OpenE2E when the server does not accept
// end-to-end encrypted streams (an exit older than v0.3).
var ErrNoE2E = errors.New("server does not support end-to-end encrypted streams")

// NeedCaps makes new tunnels ask for the server's capabilities at once
// (a relay checks them before forwarding end-to-end streams).
func (c *Cypher) NeedCaps() { c.eagerHello = true }

// SupportsE2E reports whether the server (seen as an exit) accepts
// end-to-end encrypted streams. It connects if needed.
func (c *Cypher) SupportsE2E(ctx context.Context) bool {
	t, err := c.pool.get(ctx, nil)
	if err != nil {
		return false
	}
	return t.link.serverCaps(ctx)&protocol.CapE2E != 0
}

// OpenE2E opens a stream for an end-to-end encrypted session and sends its
// header; a relay then copies the client's frames into it. The exit's
// answer (StatusE2E and its handshake frame) comes back on the stream.
func (c *Cypher) OpenE2E(ctx context.Context) (net.Conn, error) {
	var bad *tunnel
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		t, err := c.pool.get(ctx, bad)
		if err != nil {
			return nil, err
		}
		if t.link.serverCaps(ctx)&protocol.CapE2E == 0 {
			return nil, ErrNoE2E
		}
		st, err := t.sess.OpenStream()
		if err != nil {
			lastErr, bad = err, t
			continue
		}
		hdr, _ := protocol.E2ERequestHeader(protocol.Request{}, true)
		if _, err := st.Write(hdr); err != nil {
			st.Close()
			lastErr, bad = err, t
			continue
		}
		return st, nil
	}
	return nil, lastErr
}

// Dial opens a stream to dest through the server.
func (c *Cypher) Dial(ctx context.Context, dest netx.Destination) (net.Conn, error) {
	return c.openStream(ctx, protocol.Request{Cmd: protocol.CmdTCP, Dest: dest})
}

// ListenPacket opens a UDP association through the server.
func (c *Cypher) ListenPacket(ctx context.Context, dest netx.Destination) (netx.PacketConn, error) {
	st, err := c.openStream(ctx, protocol.Request{Cmd: protocol.CmdUDP, Dest: dest})
	if err != nil {
		return nil, err
	}
	return &streamPacketConn{st: st, br: bufio.NewReader(st)}, nil
}

func (c *Cypher) openStream(ctx context.Context, req protocol.Request) (net.Conn, error) {
	var lastErr error
	var bad *tunnel
	for attempt := 0; attempt < 2; attempt++ {
		t, err := c.pool.get(ctx, bad)
		if err != nil {
			return nil, err
		}
		viaRelay := c.e2e != nil && t.link.serverCaps(ctx)&protocol.CapRelay != 0
		st, err := t.sess.OpenStream()
		if err != nil {
			lastErr, bad = err, t
			continue // tunnel is dead; try another one
		}
		var conn net.Conn = st
		if viaRelay {
			conn, err = c.requestE2E(ctx, st, req)
		} else {
			err = c.request(ctx, st, req)
		}
		if err == nil {
			return conn, nil
		}
		var se protocol.StatusError
		var ee errE2E
		if errors.As(err, &se) || errors.As(err, &ee) {
			return nil, err // the server answered; reconnecting will not help
		}
		lastErr, bad = err, t
	}
	return nil, lastErr
}

// requestE2E sends req through a relay, encrypted for the exit. The relay
// may also handle the stream itself (its routing sent the destination
// elsewhere); then the stream continues in the clear like any other.
func (c *Cypher) requestE2E(ctx context.Context, st *smux.Stream, req protocol.Request) (net.Conn, error) {
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	st.SetDeadline(deadline)
	init, frame, err := protocol.NewE2EInitiator(c.e2e.pub, c.e2e.key, req)
	if err != nil {
		st.Close()
		return nil, errE2E{err}
	}
	hdr, err := protocol.E2ERequestHeader(req, c.e2e.hide)
	if err != nil {
		st.Close()
		return nil, err
	}
	if _, err := st.Write(append(hdr, frame...)); err != nil {
		st.Close()
		return nil, err
	}
	var status [1]byte
	if _, err := io.ReadFull(st, status[:]); err != nil {
		st.Close()
		return nil, err
	}
	switch status[0] {
	case protocol.StatusOK: // the relay handles it
		st.SetDeadline(time.Time{})
		return st, nil
	case protocol.StatusE2E:
		conn, err := init.Finish(st)
		if err != nil {
			st.Close()
			var se protocol.StatusError
			if errors.As(err, &se) {
				return nil, err
			}
			return nil, errE2E{err}
		}
		st.SetDeadline(time.Time{})
		return conn, nil
	default:
		st.Close()
		return nil, protocol.StatusError(status[0])
	}
}

func (c *Cypher) request(ctx context.Context, st *smux.Stream, req protocol.Request) error {
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	st.SetDeadline(deadline)
	if err := protocol.WriteRequest(st, req); err != nil {
		st.Close()
		return err
	}
	var status [1]byte
	if _, err := st.Read(status[:]); err != nil {
		st.Close()
		return err
	}
	if status[0] != protocol.StatusOK {
		st.Close()
		return protocol.StatusError(status[0])
	}
	st.SetDeadline(time.Time{})
	return nil
}

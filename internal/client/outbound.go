// Package client implements outbounds: cypher (the tunnel), direct and block.
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
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
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", dest.String())
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

var fingerprints = map[string]utls.ClientHelloID{
	"":        utls.HelloChrome_Auto,
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"random":  utls.HelloRandomized,
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

	mu   sync.Mutex
	sess *smux.Session
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
	c := &Cypher{
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
	if c.insecure {
		slog.Warn("cypher outbound: certificate verification is disabled (insecure: true) — use only for testing", "tag", c.tag)
	}
	return c, nil
}

func (c *Cypher) Tag() string { return c.tag }

func (c *Cypher) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil {
		c.sess.Close()
		c.sess = nil
	}
	return nil
}

func (c *Cypher) connect(ctx context.Context) (*smux.Session, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName:         c.serverName,
		RootCAs:            c.roots,
		InsecureSkipVerify: c.insecure,
	}, c.hello)
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := uc.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	rc := protocol.NewRecordConn(uc, protocol.BuildAuth(c.key, time.Now()))
	sess, err := smux.Client(rc, protocol.MuxConfig())
	if err != nil {
		uc.Close()
		return nil, err
	}
	slog.Info("connected to server", "outbound", c.tag, "server", c.server)
	return sess, nil
}

// session returns the shared session, reconnecting if it is closed or is the
// session that just failed (bad). Comparing against bad keeps concurrent
// failures from tearing down each other's fresh sessions.
func (c *Cypher) session(ctx context.Context, bad *smux.Session) (*smux.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil && !c.sess.IsClosed() && c.sess != bad {
		return c.sess, nil
	}
	if c.sess != nil {
		c.sess.Close()
	}
	sess, err := c.connect(ctx)
	if err != nil {
		c.sess = nil
		return nil, err
	}
	c.sess = sess
	return sess, nil
}

// Dial opens a stream to dest through the server.
func (c *Cypher) Dial(ctx context.Context, dest netx.Destination) (net.Conn, error) {
	var lastErr error
	var bad *smux.Session
	for attempt := 0; attempt < 2; attempt++ {
		sess, err := c.session(ctx, bad)
		if err != nil {
			return nil, err
		}
		st, err := sess.OpenStream()
		if err != nil {
			lastErr, bad = err, sess
			continue // session is dead; reconnect once
		}
		conn, err := c.request(ctx, st, dest)
		if err == nil {
			return conn, nil
		}
		var se protocol.StatusError
		if errors.As(err, &se) {
			return nil, err // the server answered; reconnecting will not help
		}
		lastErr, bad = err, sess
	}
	return nil, lastErr
}

func (c *Cypher) request(ctx context.Context, st *smux.Stream, dest netx.Destination) (net.Conn, error) {
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	st.SetDeadline(deadline)
	if err := protocol.WriteRequest(st, protocol.Request{Cmd: protocol.CmdTCP, Dest: dest}); err != nil {
		st.Close()
		return nil, err
	}
	var status [1]byte
	if _, err := st.Read(status[:]); err != nil {
		st.Close()
		return nil, err
	}
	if status[0] != protocol.StatusOK {
		st.Close()
		return nil, protocol.StatusError(status[0])
	}
	st.SetDeadline(time.Time{})
	return st, nil
}

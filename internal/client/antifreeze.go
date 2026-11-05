package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

// Anti-freeze modes (outbound "antiFreeze").
const (
	antiFreezeAuto = "auto" // normal tunnels; switch to segmented after a detected freeze
	antiFreezeOn   = "on"   // always segmented when the server supports it
	antiFreezeOff  = "off"
)

// How long auto mode stays segmented after a freeze before trying plain
// tunnels again.
var antiFreezeHold = 30 * time.Minute

// freezeRepeatWindow: two freezes this close together start anti-freeze mode.
var freezeRepeatWindow = 10 * time.Minute

// Carrier dial limits. Some ISPs block a server for 60–120 s after about a
// dozen TLS connections to it in a short time (reports from Nov 2025 on).
// Anti-freeze opens a connection per budget, so it must stay below that:
// at most carrierBurst new connections per carrierWindow (configurable with
// the outbound's antiFreezeRate). On dial failures the dialer backs off up
// to carrierMaxBackoff and gives up after carrierGiveUp.
var (
	carrierBurst      = 8
	carrierWindow     = 10 * time.Second
	carrierMaxBackoff = 30 * time.Second
	carrierGiveUp     = 2 * time.Minute
)

// dialLimiter allows at most n events per window.
type dialLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	times  []time.Time
}

// wait blocks until another dial is allowed (or the session closes).
func (l *dialLimiter) wait(closed func() bool) {
	for {
		l.mu.Lock()
		now := time.Now()
		kept := l.times[:0]
		for _, t := range l.times {
			if now.Sub(t) < l.window {
				kept = append(kept, t)
			}
		}
		l.times = kept
		if len(l.times) < l.n {
			l.times = append(l.times, now)
			l.mu.Unlock()
			return
		}
		next := l.times[0].Add(l.window).Sub(now)
		l.mu.Unlock()
		if closed() {
			return
		}
		time.Sleep(min(next, 500*time.Millisecond))
	}
}

func parseAntiFreeze(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", antiFreezeAuto:
		return antiFreezeAuto, nil
	case antiFreezeOn, "always":
		return antiFreezeOn, nil
	case antiFreezeOff, "never":
		return antiFreezeOff, nil
	}
	return "", fmt.Errorf("antiFreeze must be auto, on or off, got %q", s)
}

// segState tracks what we know about the server and the current mode.
type segState struct {
	mode      string
	rate      int          // carrier dials per carrierWindow
	supported atomic.Int32 // 0 unknown, 1 yes (HELLO said so), -1 no (v1 server)
	until     atomic.Int64 // auto mode: segmented until this unix nano

	lastFreeze atomic.Int64 // unix nano of the last frozen plain tunnel
}

func (st *segState) wantSegmented() bool {
	switch st.mode {
	case antiFreezeOn:
		return st.supported.Load() >= 0
	case antiFreezeAuto:
		return st.supported.Load() == 1 && time.Now().UnixNano() < st.until.Load()
	}
	return false
}

// onFreeze is called by the pool when a plain tunnel froze.
//
// Auto mode switches only on the second freeze within freezeRepeatWindow.
// A tunnel can freeze for two different reasons: the per-connection volume
// limit (~16 KB to foreign hosting; a fresh connection works again at once,
// and short connections are the cure) or a throttle on the whole server
// (new handshakes hang too, typically for ~120 s; more connections only
// make it worse). A second freeze means a reconnect worked in between, so
// it is the first kind.
func (c *Cypher) onFreeze() {
	st := &c.seg
	if st.mode != antiFreezeAuto || st.supported.Load() != 1 {
		return
	}
	now := time.Now().UnixNano()
	prev := st.lastFreeze.Swap(now)
	if now-prev > int64(freezeRepeatWindow) {
		slog.Info("connection froze; anti-freeze mode starts if it happens again", "outbound", c.tag)
		return
	}
	if time.Now().UnixNano() >= st.until.Load() {
		slog.Warn("connection freezes detected: switching to anti-freeze mode (short connections)",
			"outbound", c.tag, "for", antiFreezeHold)
	}
	st.until.Store(time.Now().Add(antiFreezeHold).UnixNano())
}

// antiFreezeBackfired ends auto mode's segmented period early when new
// connections to the server start failing.
func (c *Cypher) antiFreezeBackfired() {
	if c.seg.mode != antiFreezeAuto || time.Now().UnixNano() >= c.seg.until.Load() {
		return
	}
	c.seg.until.Store(0)
	slog.Warn("new connections to the server are failing; leaving anti-freeze mode (too many connections may be what is blocked)",
		"outbound", c.tag)
}

// AntiFreezeActive reports whether new tunnels use the segmented mode.
func (c *Cypher) AntiFreezeActive() bool { return c.seg.wantSegmented() }

// dialTLS opens a TLS connection to the server.
func (c *Cypher) dialTLS(ctx context.Context) (*utls.UConn, error) {
	addr := c.server
	if p := c.pinned.Load(); p != nil {
		addr = *p
	}
	raw, err := netx.NewDialer(10*time.Second).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	uc := utls.UClient(raw, &utls.Config{
		ServerName:         c.serverName,
		RootCAs:            c.roots,
		InsecureSkipVerify: c.insecure,
	}, c.helloID())
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := uc.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return uc, nil
}

// connectSegmented starts a session carried by short connections. With a
// server that does not support it (no HELLO), the same connection falls
// back to a plain tunnel.
func (c *Cypher) connectSegmented(ctx context.Context) (*link, error) {
	uc, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	rand.Read(id[:])
	ext := &protocol.Ext{Flags: protocol.FlagV2 | protocol.FlagSegmented, Session: id}
	rc := protocol.NewRecordConn(uc, protocol.BuildAuthExt(c.key, time.Now(), ext))
	hello := make(chan uint16, 1)
	rc.SetControlHandler(func(typ byte, body []byte) {
		if typ == protocol.CtlHello {
			if caps, ok := protocol.ParseHello(body); ok {
				select {
				case hello <- caps:
				default:
				}
			}
		}
	})
	// Send the auth header now (inside an empty data record, which a v1
	// server skips) and wait for the server's answer.
	if _, err := rc.Write(nil); err != nil {
		uc.Close()
		return nil, err
	}
	go func() { // a v1 server sends nothing; Read only returns on data or error
		buf := make([]byte, 1)
		rc.Read(buf)
	}()
	var caps uint16
	select {
	case caps = <-hello:
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
		uc.Close()
		return nil, ctx.Err()
	}
	if caps&protocol.CapSegmented == 0 {
		// Old server: it treats this connection as a plain tunnel, which is
		// what it is from now on. Remember not to try again.
		c.seg.supported.Store(-1)
		uc.Close()
		slog.Info("server does not support anti-freeze mode; using plain tunnels", "outbound", c.tag)
		return c.connectPlain(ctx)
	}
	c.seg.supported.Store(1)

	sess := protocol.NewSession(id, protocol.DefaultBudget)
	d := &carrierDialer{c: c, sess: sess, id: id,
		limit: &dialLimiter{n: c.seg.rate, window: carrierWindow}}
	sess.NeedCarrier = d.request
	sess.Attach(rc)
	ms, err := smux.Client(sess, protocol.MuxConfig())
	if err != nil {
		sess.Close()
		return nil, err
	}
	go protocol.KeepAlive(ms, sess.WriteKeepAlive, func() bool { return true }, nil, 0, 0)
	slog.Info("connected in anti-freeze mode", "outbound", c.tag, "budget", protocol.DefaultBudget)
	return &link{sess: ms, seg: sess}, nil
}

// carrierDialer opens the next carriers of a session, one at a time, for as
// long as the session wants one.
type carrierDialer struct {
	c       *Cypher
	sess    *protocol.Session
	id      [16]byte
	seq     atomic.Uint32
	running atomic.Bool

	limit *dialLimiter

	mu         sync.Mutex
	lastAttach time.Time
	quickFails int
}

func (d *carrierDialer) request(reason string) {
	d.mu.Lock()
	rejected := false
	if reason == protocol.CarrierRejected {
		// The server dropped the carrier right away: it no longer knows the
		// session (restarted, or the session expired).
		d.quickFails++
		rejected = d.quickFails >= 3
	} else if reason == "carrier closed" {
		d.quickFails = 0
	}
	d.mu.Unlock()
	if rejected {
		slog.Warn("anti-freeze session rejected by the server, starting a new one", "outbound", d.c.tag)
		d.sess.Close()
		return
	}
	if !d.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.running.Store(false)
		fails := 0
		var failingSince time.Time
		for d.sess.WantsCarrier() {
			d.limit.wait(d.sess.Closed)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := d.attach(ctx)
			cancel()
			if err == nil {
				fails, failingSince = 0, time.Time{}
				continue
			}
			fails++
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			slog.Debug("carrier dial failed", "outbound", d.c.tag, "err", err, "fails", fails)
			if fails == 3 {
				// New connections are being refused: possibly a limit on
				// connections per server, which short connections only feed.
				d.c.antiFreezeBackfired()
			}
			if time.Since(failingSince) > carrierGiveUp {
				d.sess.Close()
				return
			}
			time.Sleep(min(time.Duration(1<<min(fails-1, 5))*time.Second, carrierMaxBackoff))
		}
	}()
}

func (d *carrierDialer) attach(ctx context.Context) error {
	uc, err := d.c.dialTLS(ctx)
	if err != nil {
		return err
	}
	ext := &protocol.Ext{Flags: protocol.FlagV2 | protocol.FlagSegmented | protocol.FlagAttach,
		Session: d.id, Seq: d.seq.Add(1)}
	rc := protocol.NewRecordConn(uc, protocol.BuildAuthExt(d.c.key, time.Now(), ext))
	if d.sess.Closed() {
		uc.Close()
		return errors.New("session closed")
	}
	d.mu.Lock()
	d.lastAttach = time.Now()
	d.mu.Unlock()
	// Attach first: the auth header goes out with the first record the
	// session sends on it (the resume ACK), so the server can never switch
	// to this carrier before the client has.
	d.sess.Attach(rc)
	return nil
}

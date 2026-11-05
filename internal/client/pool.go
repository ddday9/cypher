package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/xtaci/smux"
)

// rotation holds the parsed limits; each value is an inclusive range.
type rotation struct {
	disabled         bool
	ageMin, ageMax   time.Duration
	idleMin, idleMax time.Duration
	mbMin, mbMax     int64
}

func parseRotation(rc *config.RotationConfig) (rotation, error) {
	r := rotation{
		ageMin: 5 * time.Minute, ageMax: 20 * time.Minute,
		idleMin: time.Minute, idleMax: 3 * time.Minute,
		mbMin: 64, mbMax: 512,
	}
	if rc == nil {
		return r, nil
	}
	r.disabled = rc.Disabled
	var err error
	if rc.Age != "" {
		if r.ageMin, r.ageMax, err = durationRange(rc.Age); err != nil {
			return r, fmt.Errorf("rotation.age: %w", err)
		}
	}
	if rc.Idle != "" {
		if r.idleMin, r.idleMax, err = durationRange(rc.Idle); err != nil {
			return r, fmt.Errorf("rotation.idle: %w", err)
		}
	}
	if rc.Megabytes != "" {
		if r.mbMin, r.mbMax, err = intRange(rc.Megabytes); err != nil {
			return r, fmt.Errorf("rotation.megabytes: %w", err)
		}
	}
	return r, nil
}

func durationRange(s string) (time.Duration, time.Duration, error) {
	a, b, isRange := strings.Cut(s, "-")
	lo, err := time.ParseDuration(strings.TrimSpace(a))
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if isRange {
		if hi, err = time.ParseDuration(strings.TrimSpace(b)); err != nil {
			return 0, 0, err
		}
	}
	if lo <= 0 || hi < lo {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	return lo, hi, nil
}

func intRange(s string) (int64, int64, error) {
	a, b, isRange := strings.Cut(s, "-")
	lo, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if isRange {
		if hi, err = strconv.ParseInt(strings.TrimSpace(b), 10, 64); err != nil {
			return 0, 0, err
		}
	}
	if lo <= 0 || hi < lo {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	return lo, hi, nil
}

func randDuration(lo, hi time.Duration) time.Duration {
	return lo + rand.N(hi-lo+1)
}

// tunnel is one TLS connection carrying a smux session.
type tunnel struct {
	sess     *smux.Session
	rc       *protocol.RecordConn
	link     *link
	id       int
	created  time.Time
	maxAge   time.Duration
	maxBytes int64
	idle     time.Duration

	lastUsed time.Time // guarded by pool.mu
}

func (t *tunnel) expired(now time.Time) bool {
	in, out := t.traffic()
	return now.Sub(t.created) > t.maxAge || in+out > t.maxBytes
}

// Handshake pacing. In 2026 the TSPU was reported to freeze every TLS
// connection to a server for ~120 s once more than 3 handshakes to one SNI
// start close together (within ~400 ms; some reports say within 60 s), and
// a client that keeps retrying only extends the freeze. So the pool:
//   - never has more than one handshake in flight (concurrent requests wait
//     for it instead of dialing their own);
//   - starts handshakes at least handshakeGap apart and at most
//     handshakeBurst per handshakeWindow;
//   - after a failed dial waits retryMin, doubling up to retryMax, before
//     the next attempt; requests in between fail at once.
var (
	handshakeGap    = time.Second
	handshakeBurst  = 3
	handshakeWindow = time.Minute
	retryMin        = 2 * time.Second
	retryMax        = 2 * time.Minute
	// A request waits this long at most for the pacing above; beyond that
	// it fails at once rather than hanging.
	maxPacingWait = 5 * time.Second
)

// dialCall is the handshake in flight.
type dialCall struct {
	done chan struct{}
	t    *tunnel
	err  error
}

// pool keeps up to size live tunnels and rotates them.
type pool struct {
	tag    string
	size   int
	single bool // never more than one connection, not even while rotating
	rot    rotation
	dial   func(ctx context.Context) (*link, error)
	nextID int

	mu       sync.Mutex
	active   []*tunnel
	draining []*tunnel
	inflight *dialCall
	starts   []time.Time // recent handshake starts
	fails    int         // dials failed in a row
	retryAt  time.Time
	lastErr  error
	closed   bool
	stop     chan struct{}
	started  bool
	tick     time.Duration

	freezes  atomic.Int64 // frozen tunnels detected
	onFreeze func()
}

func newPool(tag string, size int, rot rotation, dial func(context.Context) (*link, error)) *pool {
	if size <= 0 {
		// One connection, like a browser talking HTTP/2 to one site; the
		// number of parallel connections to one IP is a known DPI signal.
		size = 1
	}
	return &pool{tag: tag, size: size, rot: rot, dial: dial, stop: make(chan struct{}), tick: 5 * time.Second}
}

func (p *pool) newTunnel(l *link) *tunnel {
	p.nextID++
	t := &tunnel{sess: l.sess, rc: l.rc, link: l, id: p.nextID, created: time.Now(), lastUsed: time.Now()}
	go p.watchdog(t)
	if p.rot.disabled {
		t.maxAge, t.maxBytes, t.idle = 1<<62, 1<<62, 1<<62
	} else {
		t.maxAge = randDuration(p.rot.ageMin, p.rot.ageMax)
		t.maxBytes = (p.rot.mbMin + rand.Int64N(p.rot.mbMax-p.rot.mbMin+1)) << 20
		t.idle = randDuration(p.rot.idleMin, p.rot.idleMax)
	}
	return t
}

// tidy moves closed and expired tunnels out of the active set. Caller holds mu.
func (p *pool) tidy(now time.Time) {
	kept := p.active[:0]
	for _, t := range p.active {
		switch {
		case t.sess.IsClosed():
		case t.expired(now) && p.single:
			// Break before make: rotate only once the tunnel is unused, so
			// there is never a second connection.
			if t.sess.NumStreams() == 0 {
				slog.Debug("rotating tunnel", "outbound", p.tag, "id", t.id, "age", now.Sub(t.created).Round(time.Second))
				t.sess.Close()
				continue
			}
			kept = append(kept, t)
		case t.expired(now):
			slog.Debug("rotating tunnel", "outbound", p.tag, "id", t.id, "age", now.Sub(t.created).Round(time.Second))
			p.draining = append(p.draining, t)
		default:
			kept = append(kept, t)
		}
	}
	p.active = kept
}

// nextDial returns the earliest time a new handshake may start. Caller holds mu.
func (p *pool) nextDial(now time.Time) time.Time {
	kept := p.starts[:0]
	for _, t := range p.starts {
		if now.Sub(t) < handshakeWindow {
			kept = append(kept, t)
		}
	}
	p.starts = kept
	at := p.retryAt
	if n := len(p.starts); n > 0 {
		if gap := p.starts[n-1].Add(handshakeGap); gap.After(at) {
			at = gap
		}
		if n >= handshakeBurst {
			if w := p.starts[n-handshakeBurst].Add(handshakeWindow); w.After(at) {
				at = w
			}
		}
	}
	return at
}

// startDial begins a handshake in the background. Caller holds mu and has
// checked that none is in flight.
func (p *pool) startDial() *dialCall {
	call := &dialCall{done: make(chan struct{})}
	p.inflight = call
	p.starts = append(p.starts, time.Now())
	go func() {
		// Not tied to the caller's context: a request that gives up must not
		// waste a handshake that others are waiting for.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		l, err := p.dial(ctx)
		cancel()
		p.mu.Lock()
		p.inflight = nil
		switch {
		case err != nil:
			p.fails++
			wait := min(retryMin<<min(p.fails-1, 10), retryMax)
			wait = wait*4/5 + rand.N(wait*2/5+1) // ±20%
			p.retryAt = time.Now().Add(wait)
			p.lastErr = err
			call.err = err
			slog.Warn("cannot connect to the server", "outbound", p.tag, "err", err, "retry_in", wait.Round(time.Second))
		case p.closed:
			l.sess.Close()
			call.err = fmt.Errorf("outbound %s is closed", p.tag)
		default:
			p.fails, p.retryAt, p.lastErr = 0, time.Time{}, nil
			call.t = p.newTunnel(l)
			p.active = append(p.active, call.t)
		}
		p.mu.Unlock()
		close(call.done)
	}()
	return call
}

// get returns the least-loaded live tunnel, connecting if there is none.
// bad is a tunnel that just failed and must not be returned.
func (p *pool) get(ctx context.Context, bad *tunnel) (*tunnel, error) {
	p.mu.Lock()
	if !p.started && !p.closed {
		p.started = true
		go p.maintain()
	}
	if bad != nil {
		bad.sess.Close()
	}
	for {
		if p.closed {
			p.mu.Unlock()
			return nil, fmt.Errorf("outbound %s is closed", p.tag)
		}
		now := time.Now()
		p.tidy(now)
		var best *tunnel
		for _, t := range p.active {
			if best == nil || t.sess.NumStreams() < best.sess.NumStreams() {
				best = t
			}
		}
		if best != nil {
			// Grow the pool in the background so new streams spread out.
			if !p.single && len(p.active) < p.size && p.inflight == nil && !p.nextDial(now).After(now) {
				p.startDial()
			}
			best.lastUsed = now
			p.mu.Unlock()
			return best, nil
		}
		call := p.inflight
		if call == nil {
			if at := p.nextDial(now); at.After(now) {
				wait := at.Sub(now)
				if wait > maxPacingWait {
					err := p.lastErr
					p.mu.Unlock()
					if err == nil {
						err = errors.New("too many new connections")
					}
					return nil, fmt.Errorf("server unreachable, next attempt in %s: %w", wait.Round(time.Second), err)
				}
				p.mu.Unlock()
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				p.mu.Lock()
				continue
			}
			call = p.startDial()
		}
		p.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err != nil {
			return nil, call.err
		}
		p.mu.Lock()
		if !call.t.sess.IsClosed() {
			call.t.lastUsed = time.Now()
			p.mu.Unlock()
			return call.t, nil
		}
	}
}

// maintain closes idle tunnels and drained tunnels with no streams left.
func (p *pool) maintain() {
	tick := time.NewTicker(p.tick)
	defer tick.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-tick.C:
		}
		now := time.Now()
		p.mu.Lock()
		p.tidy(now)
		kept := p.active[:0]
		for _, t := range p.active {
			if t.sess.NumStreams() > 0 {
				t.lastUsed = now
			} else if now.Sub(t.lastUsed) > t.idle {
				slog.Debug("closing idle tunnel", "outbound", p.tag, "id", t.id)
				t.sess.Close()
				continue
			}
			kept = append(kept, t)
		}
		p.active = kept
		draining := p.draining[:0]
		for _, t := range p.draining {
			// Give long-lived streams (downloads, websockets) up to an hour.
			if t.sess.NumStreams() == 0 || now.Sub(t.created) > t.maxAge+time.Hour {
				t.sess.Close()
				continue
			}
			draining = append(draining, t)
		}
		p.draining = draining
		p.mu.Unlock()
	}
}

func (p *pool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.stop)
	for _, t := range append(p.active, p.draining...) {
		t.sess.Close()
	}
	p.active, p.draining = nil, nil
}

// stats is used by tests.
func (p *pool) stats() (active, draining int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.active), len(p.draining)
}

func (t *tunnel) traffic() (int64, int64) {
	if t.link.seg != nil {
		return t.link.seg.Traffic()
	}
	return t.rc.Traffic()
}

// link is one connected tunnel before it joins the pool.
type link struct {
	sess *smux.Session
	rc   *protocol.RecordConn // plain tunnels
	seg  *protocol.Session    // anti-freeze tunnels (carried by many connections)
	caps atomic.Uint32        // server capabilities from HELLO; 0 = protocol v1 server
	pong atomic.Uint32        // id of the last PONG received

	hello     chan struct{} // closed on HELLO, or helloWait after connecting
	helloOnce sync.Once
}

// helloWait: a server that sends no HELLO within this time is protocol v1.
var helloWait = 3 * time.Second

func newLink() *link {
	l := &link{hello: make(chan struct{})}
	time.AfterFunc(helloWait, l.helloDone)
	return l
}

func (l *link) helloDone() { l.helloOnce.Do(func() { close(l.hello) }) }

// serverCaps waits for the server's HELLO (at most helloWait after the
// connection was made) and returns its capabilities. Only features that
// need to know them before the first request wait.
func (l *link) serverCaps(ctx context.Context) uint16 {
	if l.hello != nil {
		select {
		case <-l.hello:
		case <-ctx.Done():
		}
	}
	return uint16(l.caps.Load())
}

// Freeze detection (protocol v2 servers): a censor that "freezes" a
// connection silently drops its packets without resetting it, so streams
// would hang until TCP gives up. When a tunnel with open streams goes
// silent for freezeIdle after data was flowing, or after we sent something
// that got no answer, a PING is sent; no answer within freezeTimeout means
// the tunnel is frozen and it is replaced.
//
// A tunnel that simply has nothing to say (an idle websocket) is probed
// once, not every few seconds: a steady heartbeat is itself a DPI feature.
var (
	freezeIdle    = 3 * time.Second
	freezeTimeout = 4 * time.Second
	watchTick     = time.Second
)

func (p *pool) watchdog(t *tunnel) {
	tick := time.NewTicker(watchTick)
	defer tick.Stop()
	var pingID uint32
	var pingAt time.Time
	var probedData, probedWrite time.Time // state already confirmed alive
	if t.rc == nil {
		return // anti-freeze sessions detect stalls themselves
	}
	probedData = t.rc.LastData() // nothing received yet: wait for data or an unanswered write
	for range tick.C {
		if t.sess.IsClosed() {
			return
		}
		if t.link.caps.Load()&uint32(protocol.CapPing) == 0 {
			continue
		}
		now := time.Now()
		if !pingAt.IsZero() {
			if t.link.pong.Load() == pingID || t.rc.LastRead().After(pingAt) {
				pingAt = time.Time{} // alive
			} else if now.Sub(pingAt) > freezeTimeout {
				slog.Warn("tunnel frozen (no answer from the server), reconnecting", "outbound", p.tag, "id", t.id)
				p.freezes.Add(1)
				if p.onFreeze != nil {
					p.onFreeze()
				}
				t.sess.Close()
				return
			}
			continue
		}
		last, wrote := t.rc.LastData(), t.rc.LastWrite()
		if t.sess.NumStreams() == 0 || now.Sub(last) <= freezeIdle {
			continue
		}
		unanswered := wrote.After(last) && !wrote.Equal(probedWrite) && now.Sub(wrote) > freezeIdle
		if !last.Equal(probedData) || unanswered {
			probedData, probedWrite = last, wrote
			pingID++
			pingAt = now
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], pingID)
			t.rc.WriteControl(protocol.CtlPing, b[:])
		}
	}
}

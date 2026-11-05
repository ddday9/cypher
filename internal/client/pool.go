package client

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
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
	id       int
	created  time.Time
	maxAge   time.Duration
	maxBytes int64
	idle     time.Duration

	lastUsed time.Time // guarded by pool.mu
}

func (t *tunnel) expired(now time.Time) bool {
	in, out := t.rc.Traffic()
	return now.Sub(t.created) > t.maxAge || in+out > t.maxBytes
}

// pool keeps up to size live tunnels and rotates them.
type pool struct {
	tag    string
	size   int
	rot    rotation
	dial   func(ctx context.Context) (*smux.Session, *protocol.RecordConn, error)
	nextID int

	mu       sync.Mutex
	active   []*tunnel
	draining []*tunnel
	dialing  int
	closed   bool
	stop     chan struct{}
	started  bool
	tick     time.Duration
}

func newPool(tag string, size int, rot rotation, dial func(context.Context) (*smux.Session, *protocol.RecordConn, error)) *pool {
	if size <= 0 {
		size = 2
	}
	return &pool{tag: tag, size: size, rot: rot, dial: dial, stop: make(chan struct{}), tick: 5 * time.Second}
}

func (p *pool) newTunnel(sess *smux.Session, rc *protocol.RecordConn) *tunnel {
	p.nextID++
	t := &tunnel{sess: sess, rc: rc, id: p.nextID, created: time.Now(), lastUsed: time.Now()}
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
		case t.expired(now):
			slog.Debug("rotating tunnel", "outbound", p.tag, "id", t.id, "age", now.Sub(t.created).Round(time.Second))
			p.draining = append(p.draining, t)
		default:
			kept = append(kept, t)
		}
	}
	p.active = kept
}

// get returns the least-loaded live tunnel, dialing one if there is none.
// bad is a tunnel that just failed and must not be returned.
func (p *pool) get(ctx context.Context, bad *tunnel) (*tunnel, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("outbound %s is closed", p.tag)
	}
	if !p.started {
		p.started = true
		go p.maintain()
	}
	if bad != nil {
		bad.sess.Close()
	}
	p.tidy(time.Now())
	var best *tunnel
	for _, t := range p.active {
		if best == nil || t.sess.NumStreams() < best.sess.NumStreams() {
			best = t
		}
	}
	// Grow the pool in the background so new streams spread out.
	if best != nil && len(p.active)+p.dialing < p.size {
		p.dialing++
		go p.grow()
	}
	if best != nil {
		best.lastUsed = time.Now()
		p.mu.Unlock()
		return best, nil
	}
	p.dialing++
	p.mu.Unlock()

	sess, rc, err := p.dial(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialing--
	if err != nil {
		return nil, err
	}
	t := p.newTunnel(sess, rc)
	if p.closed {
		sess.Close()
		return nil, fmt.Errorf("outbound %s is closed", p.tag)
	}
	p.active = append(p.active, t)
	return t, nil
}

func (p *pool) grow() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, rc, err := p.dial(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialing--
	if err != nil {
		slog.Debug("background dial failed", "outbound", p.tag, "err", err)
		return
	}
	if p.closed {
		sess.Close()
		return
	}
	p.active = append(p.active, p.newTunnel(sess, rc))
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

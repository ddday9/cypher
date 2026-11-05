package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/xtaci/smux"
)

// pipeDial returns a dial func backed by in-memory smux servers.
func pipeDial(t *testing.T, dials *atomic.Int32) func(context.Context) (*link, error) {
	return func(context.Context) (*link, error) {
		dials.Add(1)
		a, b := net.Pipe()
		srv, _ := smux.Server(protocol.NewRecordConn(b, nil), protocol.MuxConfig())
		go func() {
			for {
				st, err := srv.AcceptStream()
				if err != nil {
					return
				}
				go func() { buf := make([]byte, 1); st.Read(buf); st.Close() }()
			}
		}()
		rc := protocol.NewRecordConn(a, nil)
		sess, err := smux.Client(rc, protocol.MuxConfig())
		t.Cleanup(func() { sess.Close(); srv.Close() })
		return &link{sess: sess, rc: rc}, err
	}
}

func TestPoolRotation(t *testing.T) {
	var dials atomic.Int32
	rot := rotation{ageMin: 100 * time.Millisecond, ageMax: 100 * time.Millisecond,
		idleMin: time.Hour, idleMax: time.Hour, mbMin: 1 << 20, mbMax: 1 << 20}
	p := newPool("t", 1, rot, pipeDial(t, &dials))
	p.tick = 20 * time.Millisecond
	defer p.close()

	t1, err := p.get(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := t1.sess.OpenStream() // keeps t1 busy while it drains
	time.Sleep(150 * time.Millisecond)

	t2, err := p.get(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if t2 == t1 {
		t.Fatal("expired tunnel was reused")
	}
	if t1.sess.IsClosed() {
		t.Fatal("draining tunnel closed while a stream was open")
	}
	st.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !t1.sess.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !t1.sess.IsClosed() {
		t.Fatal("drained tunnel was not closed")
	}
	if dials.Load() != 2 {
		t.Fatalf("dials = %d, want 2", dials.Load())
	}
}

func TestPoolIdleAndSpread(t *testing.T) {
	fastPacing(t)
	var dials atomic.Int32
	rot := rotation{ageMin: time.Hour, ageMax: time.Hour,
		idleMin: 100 * time.Millisecond, idleMax: 100 * time.Millisecond, mbMin: 1 << 20, mbMax: 1 << 20}
	p := newPool("t", 3, rot, pipeDial(t, &dials))
	p.tick = 20 * time.Millisecond
	defer p.close()

	for range 10 {
		if _, err := p.get(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if a, _ := p.stats(); a != 3 {
		t.Fatalf("pool did not grow to 3 tunnels: %d", a)
	}
	time.Sleep(400 * time.Millisecond)
	if a, _ := p.stats(); a != 0 {
		t.Fatalf("idle tunnels were not closed: %d active", a)
	}
}

func TestParseRanges(t *testing.T) {
	if lo, hi, err := durationRange("5m-20m"); err != nil || lo != 5*time.Minute || hi != 20*time.Minute {
		t.Fatal(lo, hi, err)
	}
	for _, bad := range []string{"20m-5m", "x", "0s"} {
		if _, _, err := durationRange(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if lo, hi, err := intRange("64-512"); err != nil || lo != 64 || hi != 512 {
		t.Fatal(lo, hi, err)
	}
}

func fastPacing(t *testing.T) {
	g, b, w, rmin := handshakeGap, handshakeBurst, handshakeWindow, retryMin
	handshakeGap, handshakeBurst, handshakeWindow = 0, 100, time.Minute
	t.Cleanup(func() { handshakeGap, handshakeBurst, handshakeWindow, retryMin = g, b, w, rmin })
}

// Concurrent requests with no tunnel must share one handshake: several
// parallel TLS handshakes to one server are what triggers the throttle.
func TestPoolSingleFlight(t *testing.T) {
	var dials atomic.Int32
	inner := pipeDial(t, &dials)
	var inFlight, maxInFlight atomic.Int32
	dial := func(ctx context.Context) (*link, error) {
		n := inFlight.Add(1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		defer inFlight.Add(-1)
		return inner(ctx)
	}
	rot, _ := parseRotation(nil)
	p := newPool("t", 4, rot, dial)
	defer p.close()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.get(context.Background(), nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if maxInFlight.Load() != 1 {
		t.Fatalf("%d handshakes in flight at once, want 1", maxInFlight.Load())
	}
	if dials.Load() > 2 { // the first, plus at most one background grow started
		t.Fatalf("dials = %d", dials.Load())
	}
}

// After a failed dial, requests fail at once instead of hammering the server.
func TestPoolBackoff(t *testing.T) {
	fastPacing(t)
	retryMin = 300 * time.Millisecond
	var dials atomic.Int32
	fail := true
	var mu sync.Mutex
	inner := pipeDial(t, &dials)
	dial := func(ctx context.Context) (*link, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			dials.Add(1)
			return nil, errors.New("handshake timeout")
		}
		return inner(ctx)
	}
	rot, _ := parseRotation(nil)
	p := newPool("t", 1, rot, dial)
	defer p.close()
	if _, err := p.get(context.Background(), nil); err == nil {
		t.Fatal("dial error not returned")
	}
	// Within the backoff a request waits (up to maxPacingWait) rather than
	// starting a handshake of its own.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := p.get(ctx, nil)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || dials.Load() != 1 {
		t.Fatalf("err = %v, dials = %d; want a wait and no new dial", err, dials.Load())
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if _, err := p.get(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// Backoff beyond maxPacingWait fails fast.
	p.mu.Lock()
	p.retryAt = time.Now().Add(time.Hour)
	p.active = nil
	p.mu.Unlock()
	start := time.Now()
	if _, err := p.get(context.Background(), nil); err == nil || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("long backoff: err = %v after %v", err, time.Since(start))
	}
}

func TestPoolHandshakeBurst(t *testing.T) {
	g, b, w := handshakeGap, handshakeBurst, handshakeWindow
	handshakeGap, handshakeBurst, handshakeWindow = 0, 3, 400*time.Millisecond
	defer func() { handshakeGap, handshakeBurst, handshakeWindow = g, b, w }()
	var dials atomic.Int32
	rot, _ := parseRotation(nil)
	p := newPool("t", 1, rot, pipeDial(t, &dials))
	defer p.close()
	start := time.Now()
	var bad *tunnel
	for range 4 { // each tunnel is dropped as bad, forcing a new handshake
		tn, err := p.get(context.Background(), bad)
		if err != nil {
			t.Fatal(err)
		}
		bad = tn
	}
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Fatalf("4 handshakes in %v, want the 4th held for the window", d)
	}
}

// singleConnection: an expired tunnel keeps serving while it has streams,
// and is closed (not replaced in parallel) once idle.
func TestPoolSingleRotation(t *testing.T) {
	fastPacing(t)
	var dials atomic.Int32
	rot := rotation{ageMin: 100 * time.Millisecond, ageMax: 100 * time.Millisecond,
		idleMin: time.Hour, idleMax: time.Hour, mbMin: 1 << 20, mbMax: 1 << 20}
	p := newPool("t", 1, rot, pipeDial(t, &dials))
	p.single = true
	p.tick = 20 * time.Millisecond
	defer p.close()

	t1, err := p.get(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := t1.sess.OpenStream()
	time.Sleep(150 * time.Millisecond)
	t2, err := p.get(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if t2 != t1 || dials.Load() != 1 {
		t.Fatalf("busy expired tunnel was replaced (dials = %d)", dials.Load())
	}
	st.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !t1.sess.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !t1.sess.IsClosed() {
		t.Fatal("expired idle tunnel was not closed")
	}
	if a, d := p.stats(); a != 0 || d != 0 {
		t.Fatalf("active %d draining %d", a, d)
	}
	t3, err := p.get(context.Background(), nil)
	if err != nil || t3 == t1 || dials.Load() != 2 {
		t.Fatalf("reconnect: %v, dials = %d", err, dials.Load())
	}
}

func TestRandomFingerprintStable(t *testing.T) {
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	mk := func(server string) *Cypher {
		c, err := newCypher(config.OutboundConfig{Tag: "t", Server: server, Key: key, Fingerprint: "random"}, func(s string) string { return s })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	seen := map[string]bool{}
	for i := range 40 {
		a, b := mk(fmt.Sprintf("s%d.example:443", i)), mk(fmt.Sprintf("s%d.example:443", i))
		if a.helloID() != b.helloID() || a.helloID() != a.helloID() {
			t.Fatal("random fingerprint is not stable")
		}
		seen[a.helloID().Client] = true
	}
	if len(seen) < 2 {
		t.Fatal("random fingerprint never varies between servers")
	}
}

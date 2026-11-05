package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/protocol"
	"github.com/xtaci/smux"
)

// pipeDial returns a dial func backed by in-memory smux servers.
func pipeDial(t *testing.T, dials *int) func(context.Context) (*link, error) {
	return func(context.Context) (*link, error) {
		*dials++
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
	dials := 0
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
	if dials != 2 {
		t.Fatalf("dials = %d, want 2", dials)
	}
}

func TestPoolIdleAndSpread(t *testing.T) {
	dials := 0
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

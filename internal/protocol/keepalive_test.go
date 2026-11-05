package protocol

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestKeepAlive(t *testing.T) {
	min0, max0 := KeepAliveMin, KeepAliveMax
	KeepAliveMin, KeepAliveMax = 10*time.Millisecond, 30*time.Millisecond
	defer func() { KeepAliveMin, KeepAliveMax = min0, max0 }()

	a, b := net.Pipe()
	ca, cb := NewRecordConn(a, nil), NewRecordConn(b, nil)
	cli, _ := smux.Client(ca, MuxConfig())
	srv, _ := smux.Server(cb, MuxConfig())
	defer cli.Close()
	defer srv.Close()
	go func() {
		for {
			st, err := srv.AcceptStream()
			if err != nil {
				return
			}
			_ = st
		}
	}()

	var always atomic.Bool
	var nops atomic.Int32
	nop := func() error { nops.Add(1); return ca.WriteKeepAlive() }
	done := make(chan struct{})
	go func() { KeepAlive(cli, nop, always.Load, ca.LastRead, 0, 0); close(done) }()
	defer func() { cli.Close(); <-done }()

	time.Sleep(150 * time.Millisecond)
	if n := nops.Load(); n != 0 {
		t.Fatalf("%d keepalives on an idle session of a quiet-idle peer", n)
	}
	always.Store(true)
	time.Sleep(150 * time.Millisecond)
	if nops.Load() == 0 {
		t.Fatal("no keepalives with always")
	}
	// Keepalives arrive, but do not count as data for freeze detection.
	if cb.LastRead().IsZero() || cb.LastRead().Unix() == 0 {
		t.Fatal("keepalive not received")
	}
	if cb.LastData().Unix() != 0 {
		t.Fatal("keepalive counted as data")
	}
	if ca.LastWrite().Unix() != 0 {
		t.Fatal("keepalive counted as a data write")
	}
	always.Store(false)
	st, err := cli.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	before := nops.Load()
	time.Sleep(150 * time.Millisecond)
	if nops.Load() == before {
		t.Fatal("no keepalives with an open stream")
	}
}

func TestKeepAliveDeadPeer(t *testing.T) {
	min0, max0 := KeepAliveMin, KeepAliveMax
	KeepAliveMin, KeepAliveMax = 10*time.Millisecond, 20*time.Millisecond
	defer func() { KeepAliveMin, KeepAliveMax = min0, max0 }()
	a, b := net.Pipe()
	go func() { // a peer that reads but never answers
		buf := make([]byte, 4096)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	ca := NewRecordConn(a, nil)
	cli, _ := smux.Client(ca, MuxConfig())
	defer cli.Close()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		KeepAlive(cli, ca.WriteKeepAlive, func() bool { return true }, func() time.Time { return start }, 0, 100*time.Millisecond)
		close(done)
	}()
	defer func() { <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for !cli.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cli.IsClosed() {
		t.Fatal("session with a silent peer was not closed")
	}
}

package protocol

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// freezingLink connects a and b through a relay that silently stops
// forwarding in both directions once limit bytes went through (0 = never),
// like a censor freezing a connection.
func freezingLink(limit int) (net.Conn, net.Conn) {
	a, a2 := net.Pipe()
	b2, b := net.Pipe()
	var total atomic.Int64
	pipe := func(src, dst net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if err != nil {
				dst.Close()
				return
			}
			if limit > 0 && total.Add(int64(n)) > int64(limit) {
				continue // frozen: swallow, never close
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go pipe(a2, b2)
	go pipe(b2, a2)
	return a, b
}

type pair struct {
	client, server *Session
	mu             sync.Mutex
	dialing        bool
	carriers       int
	limit          int
	log            []string
}

// newCarrier mimics the client's dialer: it keeps attaching carriers for as
// long as the session wants one, so requests made while dialing are not lost.
func (p *pair) newCarrier(reason string) {
	p.mu.Lock()
	p.log = append(p.log, fmt.Sprintf("%s(dialing=%v)", reason, p.dialing))
	if len(p.log) > 12 {
		p.log = p.log[1:]
	}
	if p.dialing {
		p.mu.Unlock()
		return
	}
	p.dialing = true
	p.mu.Unlock()
	go func() {
		for p.client.WantsCarrier() {
			c, s := freezingLink(p.limit)
			p.server.Attach(NewRecordConn(s, nil))
			p.client.Attach(NewRecordConn(c, nil))
			p.mu.Lock()
			p.carriers++
			p.mu.Unlock()
			time.Sleep(time.Millisecond) // a real dial takes a round trip or two
		}
		p.mu.Lock()
		p.dialing = false
		p.mu.Unlock()
	}()
}

func newPair(t *testing.T, limit, budget int) *pair {
	var id [16]byte
	p := &pair{limit: limit}
	p.client = NewSession(id, budget)
	p.server = NewSession(id, budget)
	p.client.NeedCarrier = p.newCarrier
	t.Cleanup(func() { p.client.Close(); p.server.Close() })
	p.newCarrier("start")
	return p
}

func transfer(t *testing.T, p *pair, size int) {
	t.Helper()
	up, down := make([]byte, size), make([]byte, size)
	rand.Read(up)
	rand.Read(down)
	go p.client.Write(up)
	go p.server.Write(down)
	var wg sync.WaitGroup
	check := func(s *Session, want []byte, name string) {
		defer wg.Done()
		got := make([]byte, len(want))
		done := make(chan error, 1)
		go func() { _, err := io.ReadFull(s, got); done <- err }()
		select {
		case err := <-done:
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s: data mismatch (%v)", name, err)
			}
		case <-time.After(10 * time.Second):
			p.mu.Lock()
			t.Errorf("%s: timed out\n client: %s\n server: %s\n requests: %v", name, p.client.debugState(), p.server.debugState(), p.log)
			p.mu.Unlock()
		}
	}
	wg.Add(2)
	go check(p.server, up, "client→server")
	go check(p.client, down, "server→client")
	wg.Wait()
}

func TestSessionBudget(t *testing.T) {
	// No freezing: carriers are replaced only because of the budget.
	p := newPair(t, 0, DefaultBudget)
	transfer(t, p, 1<<20)
	if n := p.client.Carriers(); n < 50 {
		t.Fatalf("1 MB over 8 KB carriers used only %d carriers", n)
	}
	t.Logf("carriers: %d", p.client.Carriers())
}

func TestSessionSurvivesFreezes(t *testing.T) {
	// Carriers freeze after 6 KB — below the budget, so the stall
	// detection and retransmission have to recover every time.
	p := newPair(t, 6*1024, DefaultBudget)
	transfer(t, p, 256<<10)
	t.Logf("carriers: %d", p.client.Carriers())
}

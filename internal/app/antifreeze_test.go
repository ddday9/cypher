package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
)

// freezer is a TCP proxy that, like the TSPU, silently stops forwarding a
// connection in both directions once limit bytes went from the server to
// the client, without closing it.
func freezer(t *testing.T, upstream string, limit int64) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var frozen atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", upstream)
			if err != nil {
				c.Close()
				continue
			}
			var down atomic.Int64
			var once sync.Once
			isFrozen := func() bool { return down.Load() >= limit }
			pipe := func(dst, src net.Conn, counts bool) {
				buf := make([]byte, 16<<10)
				for {
					n, err := src.Read(buf)
					if err != nil {
						if !isFrozen() {
							dst.Close()
						}
						return
					}
					if isFrozen() {
						continue
					}
					if counts {
						if room := limit - down.Load(); int64(n) > room {
							n = int(room)
						}
						if down.Add(int64(n)) >= limit {
							once.Do(func() { frozen.Add(1) })
						}
					}
					dst.Write(buf[:n])
				}
			}
			go pipe(u, c, false)
			go pipe(c, u, true)
		}
	}()
	return ln.Addr().String(), &frozen
}

// bulkServer sends size random bytes to every connection and closes it.
func bulkServer(t *testing.T, payload []byte) netx.Destination {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.Write(payload); c.Close() }()
		}
	}()
	d, _ := netx.ParseDestination("tcp", ln.Addr().String())
	return d
}

func download(o client.Outbound, dest netx.Destination, want []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := o.Dial(ctx, dest)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	got, err := io.ReadAll(c)
	if err != nil && len(got) != len(want) {
		return err
	}
	if !bytes.Equal(got, want) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestAntiFreeze(t *testing.T) {
	e := startServer(t, true)
	front, frozen := freezer(t, e.serverAddr, 16000)
	_, port, _ := net.SplitHostPort(front)
	payload := make([]byte, 300<<10)
	rand.Read(payload)
	dest := bulkServer(t, payload)
	outbound := func(mode string) client.Outbound {
		o, err := client.New(config.OutboundConfig{
			Tag: "proxy", Type: "cypher", Server: "127.0.0.1:" + port, ServerName: "localhost",
			Key: e.key.String(), CA: e.caFile, AntiFreeze: mode,
		}, func(p string) string { return p })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { o.Close() })
		return o
	}

	// Off: a 300 KB download through a freezing network cannot finish.
	if err := download(outbound("off"), dest, payload, 3*time.Second); err == nil {
		t.Fatal("download through a freezing network succeeded without anti-freeze")
	}
	// On: short connections stay below the threshold.
	before := frozen.Load()
	if err := download(outbound("on"), dest, payload, 20*time.Second); err != nil {
		t.Fatalf("anti-freeze on: %v", err)
	}
	if frozen.Load() != before {
		t.Fatalf("anti-freeze connections reached the freeze threshold")
	}
	// Auto: the first download freezes, is detected, and the next one works.
	o := outbound("auto")
	download(o, dest, payload, 15*time.Second)
	if err := download(o, dest, payload, 20*time.Second); err != nil {
		t.Fatalf("anti-freeze auto after a freeze: %v", err)
	}
	if !o.(*client.Cypher).AntiFreezeActive() {
		t.Fatal("auto mode did not switch after a freeze")
	}
}

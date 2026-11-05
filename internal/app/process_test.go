package app

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
)

// TestProcessRule routes by the program that opened the connection: this
// test binary connects through the SOCKS inbound and its rule blocks it.
func TestProcessRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process lookup is tested on Linux")
	}
	self, _ := os.Executable()
	echo := echoServer(t)
	run := func(process string) byte {
		socks := freePort(t)
		c, err := NewClient(&config.Config{
			Dir:       t.TempDir(),
			Inbounds:  []config.InboundConfig{{Tag: "socks", Type: "socks", Listen: socks}},
			Outbounds: []config.OutboundConfig{{Tag: "direct", Type: "direct"}, {Tag: "block", Type: "block"}},
			Routing:   config.RoutingConfig{Rules: []config.RuleConfig{{Process: []string{process}, Outbound: "block"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go c.Run(ctx)
		time.Sleep(150 * time.Millisecond)
		conn, err := net.Dial("tcp", socks)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte{5, 1, 0})
		io.ReadFull(conn, make([]byte, 2))
		ap := netAddr(t, echo)
		conn.Write(append([]byte{5, 1, 0, 1}, append(ap.Addr().AsSlice(), byte(ap.Port()>>8), byte(ap.Port()))...))
		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		return rep[1]
	}
	if r := run(filepath.Base(self)); r != 2 {
		t.Fatalf("own process not blocked: SOCKS reply %d", r)
	}
	if r := run("dota2.exe"); r != 0 {
		t.Fatalf("other process rule matched: SOCKS reply %d", r)
	}
}

func netAddr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

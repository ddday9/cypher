//go:build windows

package app

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/server"
)

type fixedUpstreamWin struct{ addr string }

func (u fixedUpstreamWin) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", u.addr)
}

// TestWindowsTUN creates a real Wintun adapter with a route, the way nevio's
// "Весь трафик" mode does, and sends a connection through it. It needs
// administrator rights and wintun.dll; CI runs it with CYPHER_TUN_TEST=1.
func TestWindowsTUN(t *testing.T) {
	if os.Getenv("CYPHER_TUN_TEST") != "1" {
		t.Skip("set CYPHER_TUN_TEST=1 (administrator, wintun.dll installed)")
	}
	echo := echoServer(t)
	e := startServerWith(t, func(s *server.Server) { s.SetUpstream(fixedUpstreamWin{echo}) })
	_, port, _ := net.SplitHostPort(e.serverAddr)
	for round := 0; round < 2; round++ { // the second adapter must come up cleanly too
		c, err := NewClient(&config.Config{
			Inbounds: []config.InboundConfig{{Tag: "tun", Type: "tun", Name: "cyptest",
				Routes: []string{"10.99.1.0/24"}, DNSHijack: "off"}},
			Outbounds: []config.OutboundConfig{
				{Tag: "proxy", Type: "cypher", Server: "localhost:" + port, Key: e.key.String(), CA: e.caFile}},
			Dir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- c.Run(ctx) }()
		var conn net.Conn
		deadline := time.Now().Add(20 * time.Second)
		for {
			select {
			case err := <-errc:
				cancel()
				t.Fatalf("round %d: client stopped: %v", round, err)
			default:
			}
			conn, err = net.DialTimeout("tcp", "10.99.1.1:7", 3*time.Second)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if err != nil {
			cancel()
			t.Fatalf("round %d: dial through the TUN: %v", round, err)
		}
		echoRoundTrip(t, conn, "through wintun")
		conn.Close()
		cancel()
		<-errc
	}
}

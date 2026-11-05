//go:build windows

package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

// TestWindowsTUNDirect is nevio's "dota2.exe → напрямую" in TUN mode: the
// process is routed direct, so cypher must re-send its traffic from the
// physical interface (not back into the TUN) — TCP, TLS with a sniffed
// domain, and UDP. The proxy's upstream is an echo server, so a reply that
// is not HTTP/TLS/DNS means the traffic went through the tunnel instead.
func TestWindowsTUNDirect(t *testing.T) {
	if os.Getenv("CYPHER_TUN_TEST") != "1" {
		t.Skip("set CYPHER_TUN_TEST=1 (administrator, wintun.dll installed)")
	}
	echo := echoServer(t)
	e := startServerWith(t, func(s *server.Server) { s.SetUpstream(fixedUpstreamWin{echo}) })
	_, port, _ := net.SplitHostPort(e.serverAddr)
	exe, _ := os.Executable()
	c, err := NewClient(&config.Config{
		Inbounds: []config.InboundConfig{{Tag: "tun", Type: "tun", Name: "cypdirect",
			Routes: []string{"1.1.1.1/32", "1.0.0.1/32"}}},
		Outbounds: []config.OutboundConfig{
			{Tag: "proxy", Type: "cypher", Server: "localhost:" + port, Key: e.key.String(), CA: e.caFile},
			{Tag: "direct", Type: "direct"}},
		Routing: config.RoutingConfig{
			Rules:   []config.RuleConfig{{Process: []string{filepath.Base(exe)}, Outbound: "direct"}},
			Default: "proxy"},
		Dir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- c.Run(ctx) }()
	time.Sleep(3 * time.Second)
	select {
	case err := <-errc:
		t.Fatalf("client stopped: %v", err)
	default:
	}

	// Plain TCP.
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 10*time.Second)
	if err != nil {
		t.Fatalf("tcp: %v", err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if !strings.HasPrefix(line, "HTTP/1.") {
		t.Fatalf("tcp direct: got %q, %v (an echo means it went through the tunnel)", line, err)
	}

	// TLS: the domain is sniffed for routing, the connection must still go
	// to the address the app chose.
	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", "1.1.1.1:443",
		&tls.Config{ServerName: "one.one.one.one"})
	if err != nil {
		t.Fatalf("tls direct: %v", err)
	}
	tc.Close()

	// UDP: a DNS query.
	uc, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	var resp []byte
	for i := 0; i < 5 && resp == nil; i++ {
		uc.Write(q)
		uc.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 512)
		if n, err := uc.Read(buf); err == nil {
			resp = buf[:n]
		}
	}
	if len(resp) < 12 || resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 {
		t.Fatalf("udp direct: no DNS answer (%x)", resp)
	}
}

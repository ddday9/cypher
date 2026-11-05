package app

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"golang.org/x/net/proxy"
)

func TestSOCKSAuth(t *testing.T) {
	e := startServer(t, true)
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(e.serverAddr)
	socksAddr := freePort(t)
	c, err := NewClient(&config.Config{
		Inbounds: []config.InboundConfig{{Tag: "socks", Type: "socks", Listen: socksAddr, Username: "u1", Password: "secret"}},
		Outbounds: []config.OutboundConfig{
			{Tag: "proxy", Type: "cypher", Server: "localhost:" + port, Key: e.key.String(), CA: e.caFile}},
		Dir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	for _, tc := range []struct {
		auth *proxy.Auth
		ok   bool
	}{
		{&proxy.Auth{User: "u1", Password: "secret"}, true},
		{&proxy.Auth{User: "u1", Password: "wrong"}, false},
		{nil, false}, // no authentication offered
	} {
		d, _ := proxy.SOCKS5("tcp", socksAddr, tc.auth, &net.Dialer{Timeout: 3 * time.Second})
		conn, err := d.Dial("tcp", echo)
		if tc.ok {
			if err != nil {
				t.Fatalf("right password: %v", err)
			}
			echoRoundTrip(t, conn, "auth")
			conn.Close()
		} else if err == nil {
			conn.Close()
			t.Fatalf("SOCKS accepted %+v", tc.auth)
		}
	}
}

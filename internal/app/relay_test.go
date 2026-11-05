package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/ddday9/cypher/internal/server"
)

type node struct {
	addr, caFile, keyFile string
	srv                   *server.Server
}

func startNode(t *testing.T, cfg config.ServerConfig, rules []config.RuleConfig) node {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, _ := writeCert(t, dir)
	cfg.CertFile, cfg.KeyFile = certFile, keyFile
	cfg.AllowPrivate = true
	cfg.E2EKeyFile = filepath.Join(dir, "e2e.key")
	id := func(p string) string { return p }
	s, err := server.New(&cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouting(config.RoutingConfig{Rules: rules}, id); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, ln)
	return node{addr: ln.Addr().String(), caFile: certFile, keyFile: cfg.E2EKeyFile, srv: s}
}

func (n node) outbound(t *testing.T, oc config.OutboundConfig) client.Outbound {
	t.Helper()
	_, port, _ := net.SplitHostPort(n.addr)
	oc.Tag, oc.Type, oc.Server, oc.CA = "proxy", "cypher", "localhost:"+port, n.caFile
	o, err := client.New(oc, func(p string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func portOf(t *testing.T, addr string) config.PortList {
	_, p, _ := net.SplitHostPort(addr)
	return config.PortList(p)
}

// TestRelay runs client → relay → exit. Which server handled a stream shows
// in the rules: the exit blocks one port for everyone and another for alice
// only (so it also shows whose identity the exit saw); the relay sends one
// port direct and blocks another.
func TestRelay(t *testing.T) {
	viaDirect, exitBlocked, aliceBlocked, relayBlocked, plain := echoServer(t), echoServer(t), echoServer(t), echoServer(t), echoServer(t)
	relayKey, aliceKey, phoneKey := protocol.GenerateKey(), protocol.GenerateKey(), protocol.GenerateKey()

	exit := startNode(t, config.ServerConfig{Users: []config.UserConfig{
		{Name: "relay", Key: relayKey.String()}, {Name: "alice", Key: aliceKey.String()}}},
		[]config.RuleConfig{
			{Port: portOf(t, exitBlocked), Outbound: "block"},
			{InboundTag: []string{"alice"}, Port: portOf(t, aliceBlocked), Outbound: "block"},
		})
	ek, err := server.LoadOrCreateE2EKey(exit.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	epk := protocol.EncodeE2EPublic(ek.Public)

	_, exitPort, _ := net.SplitHostPort(exit.addr)
	relay := startNode(t, config.ServerConfig{
		Users: []config.UserConfig{{Name: "phone", Key: phoneKey.String()}},
		Upstream: &config.UpstreamConfig{OutboundConfig: config.OutboundConfig{
			Server: "localhost:" + exitPort, Key: relayKey.String(), CA: exit.caFile}},
	}, []config.RuleConfig{
		{Port: portOf(t, viaDirect), Outbound: "direct"},
		{Port: portOf(t, relayBlocked), Outbound: "block"},
	})

	type want struct {
		addr string
		ok   bool
	}
	check := func(name string, o client.Outbound, cases []want) {
		t.Helper()
		for _, c := range cases {
			dest, _ := netx.ParseDestination("tcp", c.addr)
			conn, err := o.Dial(context.Background(), dest)
			if c.ok {
				if err != nil {
					t.Fatalf("%s: %s: %v", name, c.addr, err)
				}
				echoRoundTrip(t, conn, name)
				conn.Close()
				continue
			}
			var se protocol.StatusError
			if !errors.As(err, &se) || byte(se) != protocol.StatusNotAllowed {
				t.Fatalf("%s: %s: want not allowed, got %v", name, c.addr, err)
			}
		}
	}

	// Direct to the exit, as before: alice's own rules apply.
	check("direct", exit.outbound(t, config.OutboundConfig{Key: aliceKey.String()}), []want{
		{plain, true}, {exitBlocked, false}, {aliceBlocked, false}})

	// Through the relay, decrypted there (A): the exit sees the relay.
	check("relay", relay.outbound(t, config.OutboundConfig{Key: phoneKey.String()}), []want{
		{viaDirect, true}, {plain, true}, {exitBlocked, false}, {aliceBlocked, true}, {relayBlocked, false}})

	// End to end (B): the relay still routes, the exit sees alice.
	e2e := relay.outbound(t, config.OutboundConfig{Key: phoneKey.String(), ExitKey: aliceKey.String(), ExitPublicKey: epk})
	check("e2e", e2e, []want{
		{viaDirect, true}, {plain, true}, {exitBlocked, false}, {aliceBlocked, false}, {relayBlocked, false}})

	// Anti-freeze sessions to the relay carry end-to-end streams too.
	check("e2e anti-freeze", relay.outbound(t, config.OutboundConfig{Key: phoneKey.String(), ExitKey: aliceKey.String(),
		ExitPublicKey: epk, AntiFreeze: "on", AntiFreezeRate: 1000}), []want{
		{viaDirect, true}, {plain, true}, {aliceBlocked, false}})

	// Hidden destinations: the relay cannot route, everything goes to the exit.
	check("hidden", relay.outbound(t, config.OutboundConfig{Key: phoneKey.String(), ExitKey: aliceKey.String(),
		ExitPublicKey: epk, HideDestinations: true}), []want{
		{plain, true}, {relayBlocked, true}, {aliceBlocked, false}})

	// A wrong exit key fails the handshake without breaking the tunnel.
	bad := relay.outbound(t, config.OutboundConfig{Key: phoneKey.String(), ExitKey: protocol.GenerateKey().String(), ExitPublicKey: epk})
	dest, _ := netx.ParseDestination("tcp", plain)
	if c, err := bad.Dial(context.Background(), dest); err == nil {
		t.Fatalf("unknown exit key accepted: %T %v", c, c.RemoteAddr())
	}

	// UDP end to end and through the relay.
	echo := udpEcho(t)
	udest := netx.Destination{Network: "udp", Host: echo.Addr().String(), Port: echo.Port()}
	for name, o := range map[string]client.Outbound{
		"e2e":   e2e,
		"relay": relay.outbound(t, config.OutboundConfig{Key: phoneKey.String()}),
	} {
		pc, err := o.ListenPacket(context.Background(), udest)
		if err != nil {
			t.Fatalf("%s udp: %v", name, err)
		}
		for i, size := range []int{1, 1200, 30000} {
			msg := bytes.Repeat([]byte{byte('a' + i)}, size)
			if err := pc.WritePacket(msg, udest); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 65535)
			n, _, err := pc.ReadPacket(buf)
			if err != nil || !bytes.Equal(buf[:n], append([]byte("echo:"), msg...)) {
				t.Fatalf("%s udp size %d: %d bytes, %v", name, size, n, err)
			}
		}
		pc.Close()
	}

	// Revoking alice on the exit cuts her end-to-end streams.
	dest, _ = netx.ParseDestination("tcp", plain)
	conn, err := e2e.Dial(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, conn, "before")
	if err := exit.srv.SetUsers([]config.UserConfig{{Name: "relay", Key: relayKey.String()}}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("stream of a revoked user still open")
	}
	if _, err := e2e.Dial(context.Background(), dest); err == nil {
		t.Fatal("revoked exit user accepted")
	}
}

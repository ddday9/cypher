package app

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
)

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pc.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestUDPThroughTunnel(t *testing.T) {
	e := startServer(t, true)
	o := e.outbound(t, e.key)
	echo := udpEcho(t)
	dest := netx.Destination{Network: "udp", Host: echo.Addr().String(), Port: echo.Port()}

	pc, err := o.ListenPacket(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, size := range []int{1, 1200, 60000} {
		msg := bytes.Repeat([]byte{'x'}, size)
		if err := pc.WritePacket(msg, dest); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, from, err := pc.ReadPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		if from != dest || !bytes.Equal(buf[:n], append([]byte("echo:"), msg...)) {
			t.Fatalf("size %d: from %v, got %d bytes", size, from, n)
		}
	}
}

// TestSOCKSUDPAssociate checks per-packet routing: the server refuses private
// addresses, so only the echo routed "direct" by the rule may answer.
func TestSOCKSUDPAssociate(t *testing.T) {
	e := startServer(t, false)
	_, port, _ := net.SplitHostPort(e.serverAddr)
	tunnelEcho, directEcho := udpEcho(t), udpEcho(t)
	socksAddr := freePort(t)
	c, err := NewClient(&config.Config{
		Inbounds: []config.InboundConfig{{Tag: "socks", Type: "socks", Listen: socksAddr}},
		Outbounds: []config.OutboundConfig{
			{Tag: "proxy", Type: "cypher", Server: "localhost:" + port, Key: e.key.String(), CA: e.caFile},
			{Tag: "direct", Type: "direct"},
		},
		Routing: config.RoutingConfig{Rules: []config.RuleConfig{
			{Network: "udp", Port: config.PortList(strconv.Itoa(int(directEcho.Port()))), Outbound: "direct"},
		}},
		Dir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	ctl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.SetDeadline(time.Now().Add(5 * time.Second))
	ctl.Write([]byte{5, 1, 0})
	io.ReadFull(ctl, make([]byte, 2))
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctl, rep); err != nil || rep[1] != 0 {
		t.Fatalf("associate reply %v %v", rep, err)
	}
	relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte(rep[4:8])), uint16(rep[8])<<8|uint16(rep[9]))

	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	send := func(target netip.AddrPort) ([]byte, error) {
		b := target.Addr().As4()
		pkt := append([]byte{0, 0, 0, 1}, b[:]...)
		pkt = append(pkt, byte(target.Port()>>8), byte(target.Port()), 'h', 'i')
		u.WriteToUDPAddrPort(pkt, relay)
		u.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, _, err := u.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(buf[:n], append(pkt[:10:10], []byte("echo:hi")...)) {
			t.Fatalf("%v: reply %v", target, buf[:n])
		}
		return buf[:n], nil
	}
	if _, err := send(directEcho); err != nil {
		t.Fatalf("direct rule: %v", err)
	}
	if _, err := send(tunnelEcho); err == nil {
		t.Fatal("tunnel reached a private address; routing or server filtering is broken")
	}
}

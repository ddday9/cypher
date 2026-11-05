//go:build linux

package app

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/server"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fixedUpstream struct{ addr string }

func (u fixedUpstream) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", u.addr)
}

// openTUN creates a TUN the way Android's VpnService hands it over: a file
// descriptor of an interface that is already configured.
func openTUN(t *testing.T, name string) int {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("no /dev/net/tun:", err)
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		unix.Close(fd)
		t.Skip("TUNSETIFF:", e)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netlink.ParseAddr("10.99.0.1/30")
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	_, dst, _ := net.ParseCIDR("10.99.1.0/24")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(link) })
	return fd
}

func TestTUNFromFD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	echo := echoServer(t)
	e := startServerWith(t, func(s *server.Server) { s.SetUpstream(fixedUpstream{echo}) })
	fd := openTUN(t, "cyfd0")
	_, port, _ := net.SplitHostPort(e.serverAddr)
	c, err := NewClient(&config.Config{
		Inbounds: []config.InboundConfig{{Tag: "tun", Type: "tun", FD: fd, Address6: "off", DNSHijack: "off"}},
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
	time.Sleep(300 * time.Millisecond)
	// 10.99.1.1 is routed into the TUN: the connection goes through cypher
	// and the server (whose upstream is the echo server).
	conn, err := net.DialTimeout("tcp", "10.99.1.1:7", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoRoundTrip(t, conn, "through the tun fd")
}

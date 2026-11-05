package netx

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// In TUN mode all traffic is routed into the TUN device, including our own
// connections to the server and "direct" traffic. To keep those from looping
// back into the tunnel, outgoing sockets are bound to the physical interface.

// Interface identifies the network interface outgoing sockets are bound to.
type Interface struct {
	Name  string
	Index int
}

var bound atomic.Pointer[Interface]

// SetBindInterface binds future outgoing sockets to iface (nil to unbind).
func SetBindInterface(iface *Interface) { bound.Store(iface) }

// BoundInterface returns the current binding, or nil.
func BoundInterface() *Interface { return bound.Load() }

func control(network, address string, c syscall.RawConn) error {
	iface := bound.Load()
	if iface == nil {
		return nil
	}
	// Loopback never goes through the TUN, and binding it to the physical
	// interface would make it unreachable on some systems.
	if ap, err := netip.ParseAddrPort(address); err == nil && ap.Addr().IsLoopback() {
		return nil
	}
	return bindSocket(network, address, c, iface)
}

// NewDialer returns a dialer whose sockets honour SetBindInterface.
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: control}
}

// ListenUDP opens an unconnected UDP socket that honours SetBindInterface.
func ListenUDP(ctx context.Context) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

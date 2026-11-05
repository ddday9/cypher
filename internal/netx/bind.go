package netx

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
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
// network is "udp4", "udp6" or "udp" (dual stack). While a binding is set,
// use the family of the destination: on Windows a dual-stack socket ignores
// the IPv4 binding, and its packets would go back into the TUN.
func ListenUDP(ctx context.Context, network string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: control}
	addr := ":0"
	switch network {
	case "udp4":
		addr = "0.0.0.0:0"
	case "udp6":
		addr = "[::]:0"
	}
	pc, err := lc.ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// Local ports of the sockets cypher opened for direct traffic while bound
// to the physical interface. If one of them shows up as the source of a
// TUN flow, the binding did not work and the packet came back: a loop,
// which must be dropped rather than routed again.
var ownPorts sync.Map // "udp/1234" → struct{}

func portKey(network string, port uint16) string { return network + "/" + strconv.Itoa(int(port)) }

// AddOwnPort and RemoveOwnPort track such a socket.
func AddOwnPort(network string, port uint16)    { ownPorts.Store(portKey(network, port), struct{}{}) }
func RemoveOwnPort(network string, port uint16) { ownPorts.Delete(portKey(network, port)) }

// IsOwnPort reports whether a TUN flow comes from one of cypher's own sockets.
func IsOwnPort(network string, port uint16) bool {
	_, ok := ownPorts.Load(portKey(network, port))
	return ok
}

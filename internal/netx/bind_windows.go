package netx

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

func bindSocket(network, address string, c syscall.RawConn, iface *Interface) error {
	v4only := network == "tcp4" || network == "udp4"
	v6only := network == "tcp6" || network == "udp6"
	if ap, err := netip.ParseAddrPort(address); err == nil && ap.Addr().IsValid() && !ap.Addr().IsUnspecified() {
		v4only = ap.Addr().Unmap().Is4()
		v6only = !v4only
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if !v6only {
			// IP_UNICAST_IF takes the index in network byte order.
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(iface.Index))
			idx := *(*uint32)(unsafe.Pointer(&b[0]))
			if e := windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(idx)); e != nil && v4only {
				serr = e
			}
		}
		if !v4only {
			if e := windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, iface.Index); e != nil && v6only {
				serr = e
			}
		}
	})
	if err != nil {
		return err
	}
	return serr
}

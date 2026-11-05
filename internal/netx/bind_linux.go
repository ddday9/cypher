package netx

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindSocket(_, _ string, c syscall.RawConn, iface *Interface) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.BindToDevice(int(fd), iface.Name)
	})
	if err != nil {
		return err
	}
	return serr
}

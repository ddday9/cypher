//go:build !linux && !windows

package netx

import (
	"errors"
	"syscall"
)

func bindSocket(string, string, syscall.RawConn, *Interface) error {
	return errors.New("binding sockets to an interface is not supported on this OS")
}

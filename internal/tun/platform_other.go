//go:build !linux && !windows

package tun

import (
	"errors"

	"github.com/ddday9/cypher/internal/netx"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const createHint = ""

var errUnsupported = errors.New("TUN mode is supported on Linux and Windows only")

func configure(wgtun.Device, Options) (func(), error) { return nil, errUnsupported }

func defaultInterface(string) (*netx.Interface, error) { return nil, errUnsupported }

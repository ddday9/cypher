//go:build !linux && !windows

package procinfo

import "net/netip"

func lookup(string, netip.AddrPort) (string, error) { return "", ErrNotFound }

func list() ([]Process, error) { return nil, nil }

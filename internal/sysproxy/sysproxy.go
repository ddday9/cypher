// Package sysproxy turns the operating system's proxy setting on and off.
package sysproxy

import "errors"

// ErrUnsupported is returned on systems without support.
var ErrUnsupported = errors.New("system proxy can only be set on Windows")

// Bypass lists hosts that never go through the system proxy.
const Bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// Package netx holds small networking helpers shared by the client and server.
package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// Destination is the address a proxied connection should reach.
type Destination struct {
	Network string // "tcp" or "udp"
	Host    string // domain name or IP literal
	Port    uint16
}

// ParseDestination parses "host:port".
func ParseDestination(network, hostport string) (Destination, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Destination{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Destination{}, fmt.Errorf("invalid port %q", portStr)
	}
	if host == "" {
		return Destination{}, errors.New("empty host")
	}
	return Destination{Network: network, Host: NormalizeHost(host), Port: uint16(port)}, nil
}

// NormalizeHost lowercases domain names and strips a trailing dot.
func NormalizeHost(h string) string {
	h = strings.TrimSuffix(h, ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return h
	}
	return strings.ToLower(h)
}

// Addr returns the destination IP, if Host is an IP literal.
func (d Destination) Addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(d.Host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// IsDomain reports whether Host is a domain name.
func (d Destination) IsDomain() bool {
	_, ok := d.Addr()
	return !ok
}

func (d Destination) String() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

// Relay copies data in both directions until either side finishes,
// then closes both connections.
func Relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	done := make(chan struct{})
	go func() {
		io.Copy(a, b)
		once.Do(closeBoth)
		close(done)
	}()
	io.Copy(b, a)
	once.Do(closeBoth)
	<-done
}

// PrefixConn is a net.Conn that returns Prefix before reading from Conn.
type PrefixConn struct {
	net.Conn
	Prefix []byte
}

func (c *PrefixConn) Read(p []byte) (int, error) {
	if len(c.Prefix) > 0 {
		n := copy(p, c.Prefix)
		c.Prefix = c.Prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// Dialer opens outgoing connections. Outbounds and the router implement it.
type Dialer interface {
	Dial(ctx context.Context, dest Destination) (net.Conn, error)
}

// PacketConn sends and receives datagrams to and from arbitrary destinations.
type PacketConn interface {
	ReadPacket(p []byte) (n int, from Destination, err error)
	WritePacket(p []byte, to Destination) error
	Close() error
}

type sourceKey struct{}

// Source is the local address of the application that opened a connection.
type Source struct {
	Network string // "tcp" or "udp"
	Addr    netip.AddrPort
}

// WithSource records the application's socket address in ctx.
func WithSource(ctx context.Context, network string, addr netip.AddrPort) context.Context {
	return context.WithValue(ctx, sourceKey{}, Source{network, addr})
}

// SourceFrom returns the address recorded by WithSource.
func SourceFrom(ctx context.Context) (Source, bool) {
	s, ok := ctx.Value(sourceKey{}).(Source)
	return s, ok
}

// AddrPortOf converts a net.Addr to netip.AddrPort (zero value if unknown).
func AddrPortOf(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

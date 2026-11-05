package client

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
)

// streamPacketConn carries datagrams over a cypher UDP stream.
type streamPacketConn struct {
	st  net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
	buf []byte
}

func (c *streamPacketConn) ReadPacket(p []byte) (int, netx.Destination, error) {
	return protocol.ReadPacket(c.br, p)
}

func (c *streamPacketConn) WritePacket(p []byte, to netx.Destination) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame, err := protocol.AppendPacket(c.buf[:0], to, p)
	if err != nil {
		return err
	}
	c.buf = frame
	_, err = c.st.Write(frame)
	return err
}

func (c *streamPacketConn) Close() error { return c.st.Close() }

// ListenPacket opens a local UDP socket.
func (d *Direct) ListenPacket(ctx context.Context, dest netx.Destination) (netx.PacketConn, error) {
	network := "udp"
	if netx.BoundInterface() != nil {
		// TUN mode: a socket of the destination's family, so the binding to
		// the physical interface really applies (see netx.ListenUDP). A TUN
		// flow has a single destination.
		if a, ok := dest.Addr(); ok && a.Unmap().Is4() {
			network = "udp4"
		} else if ok {
			network = "udp6"
		}
	}
	pc, err := netx.ListenUDP(ctx, network)
	if err != nil {
		return nil, err
	}
	c := &directPacketConn{pc: pc, resolved: map[string]netip.Addr{}}
	if netx.BoundInterface() != nil {
		c.port = netx.AddrPortOf(pc.LocalAddr()).Port()
		netx.AddOwnPort("udp", c.port)
	}
	return c, nil
}

type directPacketConn struct {
	pc       *net.UDPConn
	port     uint16 // registered with netx.AddOwnPort (TUN mode)
	mu       sync.Mutex
	resolved map[string]netip.Addr
}

func (c *directPacketConn) ReadPacket(p []byte) (int, netx.Destination, error) {
	n, from, err := c.pc.ReadFromUDPAddrPort(p)
	if err != nil {
		return 0, netx.Destination{}, err
	}
	return n, netx.Destination{Network: "udp", Host: from.Addr().Unmap().String(), Port: from.Port()}, nil
}

func (c *directPacketConn) WritePacket(p []byte, to netx.Destination) error {
	addr, ok := to.Addr()
	if !ok {
		c.mu.Lock()
		addr, ok = c.resolved[to.Host]
		c.mu.Unlock()
		if !ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", to.Host)
			cancel()
			if err != nil {
				return err
			}
			if len(addrs) == 0 {
				return &net.DNSError{Err: "no addresses", Name: to.Host, IsNotFound: true}
			}
			addr = addrs[0].Unmap()
			c.mu.Lock()
			c.resolved[to.Host] = addr
			c.mu.Unlock()
		}
	}
	_, err := c.pc.WriteToUDPAddrPort(p, netip.AddrPortFrom(addr, to.Port))
	return err
}

func (c *directPacketConn) Close() error {
	if c.port != 0 {
		netx.RemoveOwnPort("udp", c.port)
	}
	return c.pc.Close()
}

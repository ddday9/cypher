package app

import (
	"net"
	"sync/atomic"

	"github.com/ddday9/cypher/internal/netx"
)

// Traffic counts bytes sent to (Up) and received from (Down) the outbounds.
type Traffic struct {
	Up, Down atomic.Int64
}

// Traffic returns the bytes sent and received since the client started.
func (c *Client) Traffic() (up, down int64) {
	return c.traffic.Up.Load(), c.traffic.Down.Load()
}

type countingConn struct {
	net.Conn
	t *Traffic
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.Down.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.Up.Add(int64(n))
	return n, err
}

type countingPacketConn struct {
	netx.PacketConn
	t *Traffic
}

func (c *countingPacketConn) ReadPacket(p []byte) (int, netx.Destination, error) {
	n, from, err := c.PacketConn.ReadPacket(p)
	c.t.Down.Add(int64(n))
	return n, from, err
}

func (c *countingPacketConn) WritePacket(p []byte, to netx.Destination) error {
	err := c.PacketConn.WritePacket(p, to)
	if err == nil {
		c.t.Up.Add(int64(len(p)))
	}
	return err
}

// AntiFreezeActive reports whether any tunnel outbound currently uses the
// anti-freeze (short connections) mode.
func (c *Client) AntiFreezeActive() bool {
	for _, o := range c.outbounds {
		if a, ok := o.(interface{ AntiFreezeActive() bool }); ok && a.AntiFreezeActive() {
			return true
		}
	}
	return false
}

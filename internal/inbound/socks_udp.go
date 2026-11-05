package inbound

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
)

// handleUDPAssociate implements SOCKS5 UDP ASSOCIATE (RFC 1928 §7). The
// association lives as long as the TCP control connection. Every datagram
// is routed on its own, so one association can use several outbounds.
func (in *Inbound) handleUDPAssociate(ctx context.Context, conn net.Conn) {
	local, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	remote, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.Addr(), 0)))
	if err != nil {
		socksReply(conn, socksRepFailure)
		return
	}
	defer pc.Close()

	bound := netip.MustParseAddrPort(pc.LocalAddr().String())
	reply, _ := netx.AppendAddr([]byte{socksVersion, socksRepSuccess, 0},
		netx.Destination{Host: bound.Addr().Unmap().String(), Port: bound.Port()})
	if _, err := conn.Write(reply); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	a := &udpAssoc{in: in, ctx: ctx, pc: pc, clientIP: remote.Addr().Unmap(), outs: map[string]netx.PacketConn{}}
	defer a.close()
	go func() {
		io.Copy(io.Discard, conn) // returns when the client closes the control connection
		pc.Close()
	}()
	a.serve()
}

type udpAssoc struct {
	in       *Inbound
	ctx      context.Context
	pc       *net.UDPConn
	clientIP netip.Addr

	mu     sync.Mutex
	client netip.AddrPort // the client's UDP source, learned from its first packet
	outs   map[string]netx.PacketConn
}

func (a *udpAssoc) serve() {
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, from, err := a.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if from.Addr().Unmap() != a.clientIP {
			continue // only the client that opened the association may use it
		}
		// RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA
		if n < 4 || buf[2] != 0 {
			continue // fragmentation is not supported
		}
		dest, hl, err := netx.ParseAddr(buf[3:n], "udp")
		if err != nil {
			continue
		}
		a.mu.Lock()
		a.client = from
		a.mu.Unlock()

		out, err := a.outbound(dest)
		if err != nil {
			slog.Debug("udp dial failed", "dest", dest.String(), "err", err)
			continue
		}
		out.WritePacket(buf[3+hl:n], dest)
	}
}

func (a *udpAssoc) outbound(dest netx.Destination) (netx.PacketConn, error) {
	tag := a.in.d.RoutePacket(a.ctx, a.in.tag, dest)
	a.mu.Lock()
	defer a.mu.Unlock()
	if out, ok := a.outs[tag]; ok {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	out, err := a.in.d.ListenPacket(ctx, tag, dest)
	if err != nil {
		return nil, err
	}
	a.outs[tag] = out
	go a.pump(tag, out)
	return out, nil
}

// pump forwards replies from an outbound back to the client.
func (a *udpAssoc) pump(tag string, out netx.PacketConn) {
	defer func() {
		a.mu.Lock()
		if a.outs[tag] == out {
			delete(a.outs, tag)
		}
		a.mu.Unlock()
		out.Close()
	}()
	buf := make([]byte, protocol.MaxPacketSize)
	hdr := make([]byte, 0, 300)
	for {
		n, from, err := out.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt, err := netx.AppendAddr(append(hdr[:0], 0, 0, 0), from)
		if err != nil {
			continue
		}
		pkt = append(pkt, buf[:n]...)
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		a.pc.WriteToUDPAddrPort(pkt, client)
	}
}

func (a *udpAssoc) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, out := range a.outs {
		out.Close()
	}
	a.outs = map[string]netx.PacketConn{}
}

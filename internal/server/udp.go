package server

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
)

// udpIdleTimeout closes a UDP association after this long without packets
// in either direction.
var udpIdleTimeout = 2 * time.Minute

// handleUDP relays datagrams between a stream and the network. Each packet
// carries its own destination, so one stream can talk to many hosts (DNS,
// QUIC, games), and each packet is routed on its own: from a UDP socket of
// this server, through the exit server (relay), or dropped. The status has
// already been sent.
func (s *Server) handleUDP(st net.Conn, user *protocol.User) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		st.Close()
		return
	}
	defer pc.Close()
	slog.Debug("udp association", "user", user.Name)

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	done := make(chan struct{})
	var once sync.Once
	var exitPC netx.PacketConn // opened on the first packet routed to the exit
	var exitMu sync.Mutex
	var exitFailed time.Time // do not retry on every packet
	stop := func() {
		once.Do(func() {
			close(done)
			pc.Close()
			st.Close()
			exitMu.Lock()
			if exitPC != nil {
				exitPC.Close()
			}
			exitMu.Unlock()
		})
	}
	defer stop()

	go func() {
		t := time.NewTicker(udpIdleTimeout / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > udpIdleTimeout {
					stop()
					return
				}
			}
		}
	}()

	// Two sources write to the stream (the local socket and the exit), and
	// one packet must be one Write.
	var wmu sync.Mutex
	writeBack := func(out []byte, src netx.Destination, p []byte) ([]byte, error) {
		frame, err := protocol.AppendPacket(out[:0], src, p)
		if err != nil {
			return out, nil
		}
		wmu.Lock()
		_, err = st.Write(frame)
		wmu.Unlock()
		return frame, err
	}

	// remote → client
	go func() {
		defer stop()
		buf := make([]byte, protocol.MaxPacketSize)
		out := make([]byte, 0, protocol.MaxPacketSize+32)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			touch()
			src := netx.Destination{Network: "udp", Host: from.Addr().Unmap().String(), Port: from.Port()}
			if out, err = writeBack(out, src, buf[:n]); err != nil {
				return
			}
		}
	}()

	openExit := func(dest netx.Destination) netx.PacketConn {
		exitMu.Lock()
		defer exitMu.Unlock()
		if exitPC != nil {
			return exitPC
		}
		if time.Since(exitFailed) < 5*time.Second {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*dialTimeout)
		c, err := s.exit.ListenPacket(ctx, dest)
		cancel()
		if err != nil {
			slog.Debug("udp to the exit failed", "user", user.Name, "err", err)
			exitFailed = time.Now()
			return nil
		}
		exitPC = c
		go func() { // exit → client
			defer stop()
			buf := make([]byte, protocol.MaxPacketSize)
			out := make([]byte, 0, protocol.MaxPacketSize+32)
			for {
				n, src, err := c.ReadPacket(buf)
				if err != nil {
					return
				}
				touch()
				if out, err = writeBack(out, src, buf[:n]); err != nil {
					return
				}
			}
		}()
		return c
	}

	// client → remote
	resolved := map[string]netip.Addr{}
	br := bufio.NewReader(st)
	buf := make([]byte, protocol.MaxPacketSize)
	for {
		n, dest, err := protocol.ReadPacket(br, buf)
		if err != nil {
			return
		}
		touch()
		switch s.route(user.Name, dest) {
		case routeBlock:
		case routeExit:
			if c := openExit(dest); c != nil {
				c.WritePacket(buf[:n], dest)
			}
		default:
			if addr, ok := s.resolveUDP(dest, resolved); ok {
				pc.WriteToUDPAddrPort(buf[:n], netip.AddrPortFrom(addr, dest.Port))
			}
		}
	}
}

// resolveUDP returns an allowed address for dest, caching domain lookups for
// the lifetime of the association.
func (s *Server) resolveUDP(dest netx.Destination, cache map[string]netip.Addr) (netip.Addr, bool) {
	if a, ok := dest.Addr(); ok {
		return a, s.allowPrivate || !isPrivate(a)
	}
	if a, ok := cache[dest.Host]; ok {
		return a, a.IsValid()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := s.resolver.LookupNetIP(ctx, "ip", dest.Host)
	var chosen netip.Addr
	if err == nil {
		for _, a := range addrs {
			a = a.Unmap()
			if s.allowPrivate || !isPrivate(a) {
				chosen = a
				break
			}
		}
	}
	cache[dest.Host] = chosen // an invalid entry caches the failure too
	return chosen, chosen.IsValid()
}

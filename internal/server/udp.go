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
	"github.com/xtaci/smux"
)

// udpIdleTimeout closes a UDP association after this long without packets
// in either direction.
var udpIdleTimeout = 2 * time.Minute

// handleUDP relays datagrams between a stream and a UDP socket on the server.
// Each packet carries its own destination, so one stream can talk to many
// hosts (DNS, QUIC, games).
func (s *Server) handleUDP(st *smux.Stream, user *protocol.User) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		st.Write([]byte{protocol.StatusFailure})
		return
	}
	defer pc.Close()
	if _, err := st.Write([]byte{protocol.StatusOK}); err != nil {
		return
	}
	st.SetDeadline(time.Time{})
	slog.Debug("udp association", "user", user.Name)

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			pc.Close()
			st.Close()
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
			frame, err := protocol.AppendPacket(out[:0], src, buf[:n])
			if err != nil {
				continue
			}
			if _, err := st.Write(frame); err != nil {
				return
			}
		}
	}()

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
		if s.blocked(user.Name, dest) {
			continue
		}
		addr, ok := s.resolveUDP(dest, resolved)
		if !ok {
			continue
		}
		pc.WriteToUDPAddrPort(buf[:n], netip.AddrPortFrom(addr, dest.Port))
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

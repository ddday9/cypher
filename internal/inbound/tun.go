package inbound

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/ddday9/cypher/internal/sniff"
	"github.com/ddday9/cypher/internal/tun"
)

const (
	sniffTimeout   = 300 * time.Millisecond
	udpFlowTimeout = time.Minute
	dnsFlowTimeout = 15 * time.Second
)

// tunInbound captures system traffic through a TUN device.
type tunInbound struct {
	in        *Inbound
	opts      tun.Options
	dnsHijack *netx.Destination
	sniff     bool
	ctx       context.Context
}

func newTUN(in *Inbound, cfg config.InboundConfig) (*tunInbound, error) {
	t := &tunInbound{in: in, sniff: cfg.Sniff == nil || *cfg.Sniff}
	o := tun.Options{Name: cfg.Name, MTU: cfg.MTU, AutoRoute: cfg.AutoRoute == nil || *cfg.AutoRoute, FD: cfg.FD}
	if o.Name == "" {
		o.Name = "cypher"
	}
	if o.MTU == 0 {
		o.MTU = 1500
	}
	addr := cfg.Address
	if addr == "" {
		addr = "172.19.0.1/30"
	}
	p, err := netip.ParsePrefix(addr)
	if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
		return nil, fmt.Errorf("tun: address must be an IPv4 prefix of /30 or larger, got %q", addr)
	}
	o.Address4 = p
	// The OS is told to use the next address in the subnet as its DNS server;
	// queries to it enter the TUN and are hijacked.
	o.DNS = p.Addr().Next()
	switch cfg.Address6 {
	case "off":
	case "":
		o.Address6 = netip.MustParsePrefix("fdfe:dcba:9876::1/126")
	default:
		if o.Address6, err = netip.ParsePrefix(cfg.Address6); err != nil || !o.Address6.Addr().Is6() {
			return nil, fmt.Errorf("tun: invalid address6 %q", cfg.Address6)
		}
	}
	if len(cfg.Routes) == 0 {
		o.Routes = tun.DefaultRoutes
	}
	for _, r := range cfg.Routes {
		rp, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("tun: invalid route %q", r)
		}
		o.Routes = append(o.Routes, rp.Masked())
	}
	t.opts = o
	switch strings.ToLower(cfg.DNSHijack) {
	case "off":
	case "":
		d := netx.Destination{Host: "1.1.1.1", Port: 53}
		t.dnsHijack = &d
	default:
		d, err := netx.ParseDestination("udp", cfg.DNSHijack)
		if err != nil {
			return nil, fmt.Errorf("tun: dnsHijack: %w", err)
		}
		t.dnsHijack = &d
	}
	return t, nil
}

func (t *tunInbound) serve(ctx context.Context) error {
	t.ctx = ctx
	dev, err := tun.Open(t.opts, t)
	if err != nil {
		return err
	}
	<-ctx.Done()
	dev.Close()
	return nil
}

func (t *tunInbound) isDNS(dst netip.AddrPort) bool {
	return t.dnsHijack != nil && dst.Port() == 53
}

// HandleTCP implements tun.Handler.
func (t *tunInbound) HandleTCP(conn net.Conn, src, dst netip.AddrPort) {
	ctx := netx.WithSource(t.ctx, "tcp", src)
	dest := netx.Destination{Network: "tcp", Host: dst.Addr().String(), Port: dst.Port()}
	var c net.Conn = conn
	if t.isDNS(dst) {
		dest.Host, dest.Port = t.dnsHijack.Host, t.dnsHijack.Port
	} else if t.sniff {
		domain, buf := sniff.Peek(conn, sniffTimeout)
		if len(buf) > 0 {
			c = &netx.PrefixConn{Conn: conn, Prefix: buf}
		}
		if domain != "" {
			slog.Debug("sniffed", "ip", dst.String(), "domain", domain)
			dest.Host = domain
		}
	}
	target, err := t.in.dial(ctx, dest)
	if err != nil {
		conn.Close()
		return
	}
	netx.Relay(c, target)
}

// HandleUDP implements tun.Handler. conn is bound to (src, dst): reads return
// datagrams from the application, writes go back to it from dst.
func (t *tunInbound) HandleUDP(conn net.Conn, src, dst netip.AddrPort) {
	defer conn.Close()
	dest := netx.Destination{Network: "udp", Host: dst.Addr().String(), Port: dst.Port()}
	timeout := udpFlowTimeout
	if t.isDNS(dst) {
		dest.Host, dest.Port = t.dnsHijack.Host, t.dnsHijack.Port
		timeout = dnsFlowTimeout
	}
	sctx := netx.WithSource(t.ctx, "udp", src)
	tag := t.in.d.RoutePacket(sctx, t.in.tag, dest)
	ctx, cancel := context.WithTimeout(sctx, 30*time.Second)
	pc, err := t.in.d.ListenPacket(ctx, tag, dest)
	cancel()
	if err != nil {
		slog.Debug("udp flow failed", "dest", dest.String(), "err", err)
		return
	}
	var once sync.Once
	stop := func() { once.Do(func() { pc.Close(); conn.Close() }) }
	defer stop()

	var lastRemote atomic.Int64
	go func() { // remote → application
		defer stop()
		buf := make([]byte, protocol.MaxPacketSize)
		for {
			n, _, err := pc.ReadPacket(buf)
			if err != nil {
				return
			}
			lastRemote.Store(time.Now().UnixNano())
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, protocol.MaxPacketSize)
	for { // application → remote
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() &&
				time.Since(time.Unix(0, lastRemote.Load())) < timeout {
				continue // the remote side is still active
			}
			return
		}
		if err := pc.WritePacket(buf[:n], dest); err != nil {
			return
		}
	}
}

package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Options configure the TUN interface.
type Options struct {
	Name      string
	MTU       int
	Address4  netip.Prefix // e.g. 172.19.0.1/30
	Address6  netip.Prefix // e.g. fdfe:dcba:9876::1/126
	DNS       netip.Addr   // DNS server announced to the OS (inside Address4)
	AutoRoute bool
	Routes    []netip.Prefix // routed into the interface when AutoRoute is on
}

// DefaultRoutes send everything into the TUN while staying more specific than
// the system default route (which is left untouched and restored for free).
var DefaultRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"),
	netip.MustParsePrefix("8000::/1"),
}

// Device is a configured TUN interface with a running stack.
type Device struct {
	dev     wgtun.Device
	stack   *Stack
	cleanup func()
	cancel  context.CancelFunc
}

// Open creates the interface, configures addresses and routes, binds our
// own outgoing sockets to the physical interface and starts the stack.
func Open(opts Options, h Handler) (*Device, error) {
	// Find the physical interface before our routes take over.
	phys, err := defaultInterface("")
	if err != nil {
		return nil, fmt.Errorf("find the default network interface: %w", err)
	}
	dev, err := wgtun.CreateTUN(opts.Name, opts.MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w%s", opts.Name, err, createHint)
	}
	name, _ := dev.Name()
	opts.Name = name
	netx.SetBindInterface(phys)
	slog.Info("outgoing traffic bound to interface", "name", phys.Name, "index", phys.Index)

	cleanup, err := configure(dev, opts)
	if err != nil {
		dev.Close()
		netx.SetBindInterface(nil)
		return nil, err
	}
	st, err := NewStack(dev, opts.MTU, h)
	if err != nil {
		cleanup()
		dev.Close()
		netx.SetBindInterface(nil)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Device{dev: dev, stack: st, cleanup: cleanup, cancel: cancel}
	go d.monitor(ctx, name)
	slog.Info("TUN started", "name", name, "address", opts.Address4, "autoRoute", opts.AutoRoute)
	return d, nil
}

// monitor follows changes of the default interface (Wi-Fi ↔ Ethernet).
func (d *Device) monitor(ctx context.Context, tunName string) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := netx.BoundInterface()
		phys, err := defaultInterface(tunName)
		if err != nil || phys == nil {
			continue
		}
		if cur == nil || cur.Index != phys.Index || cur.Name != phys.Name {
			netx.SetBindInterface(phys)
			slog.Info("default interface changed", "name", phys.Name, "index", phys.Index)
		}
	}
}

// Close removes routes and the interface.
func (d *Device) Close() {
	d.cancel()
	d.stack.Close()
	d.cleanup()
	d.dev.Close()
	netx.SetBindInterface(nil)
}

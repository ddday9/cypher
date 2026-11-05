package tun

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const createHint = " (run as root or with CAP_NET_ADMIN)"

func prefixToNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func configure(dev wgtun.Device, opts Options) (func(), error) {
	link, err := netlink.LinkByName(opts.Name)
	if err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixToNet(opts.Address4)}); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("set address: %w", err)
	}
	if opts.Address6.IsValid() {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixToNet(opts.Address6)}); err != nil && !errors.Is(err, unix.EEXIST) {
			slog.Warn("IPv6 address not set", "err", err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("link up: %w", err)
	}
	var added []*netlink.Route
	if opts.AutoRoute {
		for _, p := range opts.Routes {
			if p.Addr().Is6() && !opts.Address6.IsValid() {
				continue
			}
			r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToNet(p), Scope: netlink.SCOPE_LINK}
			if err := netlink.RouteAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
				if p.Addr().Is6() {
					slog.Warn("IPv6 route not added", "route", p, "err", err)
					continue
				}
				return nil, fmt.Errorf("add route %s: %w", p, err)
			}
			added = append(added, r)
		}
		// Send all DNS lookups of systemd-resolved to the TUN (best effort).
		if path, err := exec.LookPath("resolvectl"); err == nil && opts.DNS.IsValid() {
			if out, err := exec.Command(path, "dns", opts.Name, opts.DNS.String()).CombinedOutput(); err != nil {
				slog.Warn("resolvectl dns failed", "err", err, "out", string(out))
			} else {
				exec.Command(path, "domain", opts.Name, "~.").Run()
				exec.Command(path, "default-route", opts.Name, "true").Run()
			}
		}
	}
	return func() {
		for _, r := range added {
			netlink.RouteDel(r)
		}
	}, nil
}

// defaultInterface returns the interface of the IPv4 default route, ignoring
// the TUN itself.
func defaultInterface(skip string) (*netx.Interface, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var best *netlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if best == nil || r.Priority < best.Priority {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil || link.Attrs().Name == skip {
				continue
			}
			best = r
		}
	}
	if best == nil {
		return nil, errors.New("no default route")
	}
	link, err := netlink.LinkByIndex(best.LinkIndex)
	if err != nil {
		return nil, err
	}
	return &netx.Interface{Name: link.Attrs().Name, Index: best.LinkIndex}, nil
}

func createFromFD(fd int) (wgtun.Device, string, error) { return wgtun.CreateUnmonitoredTUNFromFD(fd) }

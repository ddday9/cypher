package tun

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const createHint = " (run as Administrator; wintun.dll must be next to cypher.exe — download it from https://www.wintun.net)"

// Right after the adapter is created Windows may not have finished setting
// up its IP interface and answers ERROR_NOT_FOUND; wireguard-windows
// retries in the same way.
func retryNotFound(f func() error) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = f(); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}

// setAddresses assigns the adapter's address. If an adapter left over from
// a crash still holds it, the address is removed there first.
func setAddresses(luid winipcfg.LUID, family winipcfg.AddressFamily, p netip.Prefix) error {
	err := retryNotFound(func() error { return luid.SetIPAddressesForFamily(family, []netip.Prefix{p}) })
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		removeStaleAddress(family, p.Addr())
		err = retryNotFound(func() error { return luid.SetIPAddressesForFamily(family, []netip.Prefix{p}) })
	}
	return err
}

func removeStaleAddress(family winipcfg.AddressFamily, addr netip.Addr) {
	ifaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for a := iface.FirstUnicastAddress; a != nil; a = a.Next {
			if ip, ok := netip.AddrFromSlice(a.Address.IP()); ok && ip.Unmap() == addr {
				prefix := netip.PrefixFrom(addr, int(a.OnLinkPrefixLength))
				slog.Info("removing a stale address from an old adapter", "address", prefix, "adapter", iface.FriendlyName())
				iface.LUID.DeleteIPAddress(prefix)
			}
		}
	}
}

// addRoutes adds routes to the adapter. The adapter is new, so nothing is
// flushed first: flushing would also try to delete the routes Windows has
// just created for the address, which can fail with ERROR_NOT_FOUND.
func addRoutes(luid winipcfg.LUID, routes []netip.Prefix, nextHop netip.Addr) error {
	for _, p := range routes {
		err := retryNotFound(func() error { return luid.AddRoute(p, nextHop, 0) })
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("add route %s: %w", p, err)
		}
	}
	return nil
}

func configure(dev wgtun.Device, opts Options) (func(), error) {
	nt, ok := dev.(*wgtun.NativeTun)
	if !ok {
		return nil, errors.New("unexpected TUN device type")
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := setAddresses(luid, windows.AF_INET, opts.Address4); err != nil {
		return nil, fmt.Errorf("set address: %w", err)
	}
	has6 := false
	if opts.Address6.IsValid() {
		if err := setAddresses(luid, windows.AF_INET6, opts.Address6); err != nil {
			slog.Warn("IPv6 address not set", "err", err)
		} else {
			has6 = true
		}
	}
	if opts.AutoRoute {
		var r4, r6 []netip.Prefix
		for _, p := range opts.Routes {
			if p.Addr().Is4() {
				r4 = append(r4, p)
			} else if has6 {
				r6 = append(r6, p)
			}
		}
		if err := addRoutes(luid, r4, netip.IPv4Unspecified()); err != nil {
			return nil, fmt.Errorf("set routes: %w", err)
		}
		if err := addRoutes(luid, r6, netip.IPv6Unspecified()); err != nil {
			slog.Warn("IPv6 routes not set", "err", err)
		}
		// Lowest metric, so Windows prefers this interface and its DNS server.
		for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			if fam == windows.AF_INET6 && !has6 {
				continue
			}
			err := retryNotFound(func() error {
				iface, err := luid.IPInterface(fam)
				if err != nil {
					return err
				}
				iface.UseAutomaticMetric = false
				iface.Metric = 0
				iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
				iface.DadTransmits = 0
				return iface.Set()
			})
			if err != nil {
				slog.Warn("set interface metric failed", "err", err)
			}
		}
		if opts.DNS.IsValid() {
			if err := retryNotFound(func() error { return luid.SetDNS(windows.AF_INET, []netip.Addr{opts.DNS}, nil) }); err != nil {
				slog.Warn("set DNS failed", "err", err)
			}
		}
	}
	// Routes and addresses disappear together with the adapter.
	return func() {}, nil
}

// defaultInterface returns the interface of the best IPv4 default route,
// ignoring the TUN itself (skip is its name).
func defaultInterface(skip string) (*netx.Interface, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	var best *winipcfg.MibIPforwardRow2
	bestMetric := ^uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		ifc, err := r.InterfaceLUID.Interface()
		if err != nil || (skip != "" && ifc.Alias() == skip) {
			continue
		}
		metric := r.Metric
		if ipif, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			metric += ipif.Metric
		}
		if metric < bestMetric {
			best, bestMetric = r, metric
		}
	}
	if best == nil {
		return nil, errors.New("no default route")
	}
	name := ""
	if ifc, err := best.InterfaceLUID.Interface(); err == nil {
		name = ifc.Alias()
	}
	return &netx.Interface{Name: name, Index: int(best.InterfaceIndex)}, nil
}

func createFromFD(int) (wgtun.Device, string, error) {
	return nil, "", errors.New("a TUN file descriptor is only used on Android")
}

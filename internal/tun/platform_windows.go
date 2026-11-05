package tun

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/ddday9/cypher/internal/netx"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const createHint = " (run as Administrator; wintun.dll must be next to cypher.exe — download it from https://www.wintun.net)"

func configure(dev wgtun.Device, opts Options) (func(), error) {
	nt, ok := dev.(*wgtun.NativeTun)
	if !ok {
		return nil, errors.New("unexpected TUN device type")
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{opts.Address4}); err != nil {
		return nil, fmt.Errorf("set address: %w", err)
	}
	has6 := false
	if opts.Address6.IsValid() {
		if err := luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{opts.Address6}); err != nil {
			slog.Warn("IPv6 address not set", "err", err)
		} else {
			has6 = true
		}
	}
	if opts.AutoRoute {
		var r4, r6 []*winipcfg.RouteData
		for _, p := range opts.Routes {
			if p.Addr().Is4() {
				r4 = append(r4, &winipcfg.RouteData{Destination: p, NextHop: netip.IPv4Unspecified()})
			} else if has6 {
				r6 = append(r6, &winipcfg.RouteData{Destination: p, NextHop: netip.IPv6Unspecified()})
			}
		}
		if err := luid.SetRoutesForFamily(windows.AF_INET, r4); err != nil {
			return nil, fmt.Errorf("set routes: %w", err)
		}
		if len(r6) > 0 {
			if err := luid.SetRoutesForFamily(windows.AF_INET6, r6); err != nil {
				slog.Warn("IPv6 routes not set", "err", err)
			}
		}
		// Lowest metric, so Windows prefers this interface and its DNS server.
		for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			if iface, err := luid.IPInterface(fam); err == nil {
				iface.UseAutomaticMetric = false
				iface.Metric = 0
				if err := iface.Set(); err != nil {
					slog.Warn("set interface metric failed", "err", err)
				}
			}
		}
		if opts.DNS.IsValid() {
			if err := luid.SetDNS(windows.AF_INET, []netip.Addr{opts.DNS}, nil); err != nil {
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

package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/geo"
)

// geoPaths returns where geosite.dat and geoip.dat live for cfg.
func geoPaths(cfg *config.Config) (site, ip string) {
	site, ip = cfg.Routing.Geosite, cfg.Routing.Geoip
	if site == "" {
		site = "geosite.dat"
	}
	if ip == "" {
		ip = "geoip.dat"
	}
	return cfg.Resolve(site), cfg.Resolve(ip)
}

// geoSources lists the files to keep updated and how often.
func geoSources(cfg *config.Config) ([]geo.Source, time.Duration, error) {
	site, ip := geoPaths(cfg)
	var srcs []geo.Source
	// Rules that use geosite:/geoip: get the runetfreedom lists unless
	// another source is set ("none" keeps local files without updates).
	needSite, needIP := usesGeo(cfg.Routing)
	if u := geoURL(cfg.Routing.GeositeURL, needSite, geo.DefaultGeositeURL); u != "" {
		srcs = append(srcs, geo.Source{URL: u, Path: site})
	}
	if u := geoURL(cfg.Routing.GeoipURL, needIP, geo.DefaultGeoipURL); u != "" {
		srcs = append(srcs, geo.Source{URL: u, Path: ip})
	}
	interval, err := geo.ParseInterval(cfg.Routing.GeoUpdate)
	if err != nil {
		return nil, 0, err
	}
	return srcs, interval, nil
}

func geoURL(set string, needed bool, def string) string {
	switch strings.ToLower(strings.TrimSpace(set)) {
	case "none", "off":
		return ""
	case "":
		if needed {
			return def
		}
		return ""
	}
	return set
}

// usesGeo reports whether any rule refers to geosite: or geoip: lists.
func usesGeo(rc config.RoutingConfig) (site, ip bool) {
	for _, r := range rc.Rules {
		for _, d := range r.Domain {
			if strings.HasPrefix(strings.ToLower(d), "geosite:") {
				site = true
			}
		}
		for _, a := range r.IP {
			if strings.HasPrefix(strings.ToLower(strings.TrimPrefix(a, "!")), "geoip:") {
				ip = true
			}
		}
	}
	return site, ip
}

// ensureGeo downloads missing geo files before the router needs them.
func ensureGeo(ctx context.Context, srcs []geo.Source) error {
	if len(srcs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := geo.EnsureAll(ctx, srcs); err != nil {
		for _, s := range srcs {
			if _, statErr := os.Stat(s.Path); statErr != nil {
				return fmt.Errorf("download %s: %w", s.Path, err)
			}
		}
		slog.Warn("geo download failed, using existing files", "err", err)
	}
	return nil
}

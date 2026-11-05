package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
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
	if u := cfg.Routing.GeositeURL; u != "" {
		srcs = append(srcs, geo.Source{URL: u, Path: site})
	}
	if u := cfg.Routing.GeoipURL; u != "" {
		srcs = append(srcs, geo.Source{URL: u, Path: ip})
	}
	interval, err := geo.ParseInterval(cfg.Routing.GeoUpdate)
	if err != nil {
		return nil, 0, err
	}
	return srcs, interval, nil
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

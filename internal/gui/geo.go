package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ddday9/cypher/internal/geo"
	"github.com/ddday9/cypher/internal/router"
)

const (
	geositeFile = "geosite.dat"
	geoipFile   = "geoip.dat"
)

func (a *App) geoPath(name string) string { return filepath.Join(a.dir, name) }

func (a *App) haveGeo() bool {
	for _, f := range []string{geositeFile, geoipFile} {
		if st, err := os.Stat(a.geoPath(f)); err != nil || st.Size() == 0 {
			return false
		}
	}
	return true
}

// UpdateGeo downloads both geo files. A running client picks the new files
// up by itself, without reconnecting. It does not mark the app busy: a
// background refresh must never block the connect button.
func (a *App) UpdateGeo(ctx context.Context) error {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	st := a.store.Get().Settings
	for _, f := range []struct{ url, name string }{{st.GeositeURL, geositeFile}, {st.GeoipURL, geoipFile}} {
		if f.url == "" {
			return fmt.Errorf("не задана ссылка на %s", f.name)
		}
		if err := geo.Download(ctx, f.url, a.geoPath(f.name)); err != nil {
			return fmt.Errorf("загрузка %s: %w", f.name, err)
		}
	}
	slog.Info("geo files updated")
	return a.store.Update(func(s *State) error { s.Settings.GeoUpdated = time.Now(); return nil })
}

// geoLoop refreshes the geo files on the configured period.
func (a *App) geoLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		st := a.store.Get().Settings
		period := time.Duration(st.GeoInterval) * time.Hour
		if st.GeoAuto && period > 0 && a.haveGeo() && time.Since(st.GeoUpdated) > period {
			if err := a.UpdateGeo(ctx); err != nil {
				slog.Warn("geo auto-update failed", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// GeoCategories lists the geosite and geoip categories of the current
// files, for suggestions in the rule editor. Cached until the files change.
func (a *App) GeoCategories() (site, ip []string) {
	a.catMu.Lock()
	defer a.catMu.Unlock()
	load := func(name string, c *catCache) []string {
		st, err := os.Stat(a.geoPath(name))
		if err != nil {
			return nil
		}
		if c.list == nil || !st.ModTime().Equal(c.mod) || st.Size() != c.size {
			list, err := router.Categories(a.geoPath(name))
			if err != nil {
				return c.list
			}
			c.list, c.mod, c.size = list, st.ModTime(), st.Size()
		}
		return c.list
	}
	return load(geositeFile, &a.catSite), load(geoipFile, &a.catIP)
}

type catCache struct {
	list []string
	mod  time.Time
	size int64
}

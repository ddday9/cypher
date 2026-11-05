package gui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
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

// download fetches url into the data directory atomically, so a running
// client (which watches the file) never sees a half-written file.
func (a *App) download(ctx context.Context, url, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(a.dir, name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.geoPath(name))
}

// UpdateGeo downloads both geo files.
func (a *App) UpdateGeo(ctx context.Context) error {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	st := a.store.Get().Settings
	a.setBusy("Загружаю базы geosite и geoip…")
	defer a.setBusy("")
	for _, f := range []struct{ url, name string }{{st.GeositeURL, geositeFile}, {st.GeoipURL, geoipFile}} {
		if err := a.download(ctx, f.url, f.name); err != nil {
			return fmt.Errorf("загрузка %s: %w", f.name, err)
		}
	}
	slog.Info("geo files updated")
	return a.store.Update(func(s *State) error { s.Settings.GeoUpdated = time.Now(); return nil })
}

// geoLoop refreshes the geo files once a day when enabled.
func (a *App) geoLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		st := a.store.Get().Settings
		if st.GeoAuto && a.haveGeo() && time.Since(st.GeoUpdated) > 24*time.Hour {
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

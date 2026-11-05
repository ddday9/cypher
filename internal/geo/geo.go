// Package geo downloads geosite.dat / geoip.dat and keeps them fresh with a
// built-in timer (no cron needed). Files are replaced atomically, so the
// router, which watches them, never reads a half-written file.
package geo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Source is a file kept up to date from a URL.
type Source struct {
	URL  string
	Path string
}

// Known source sets offered in the UI.
type Preset struct {
	ID, Name, Geosite, Geoip, Note string
}

var Presets = []Preset{
	{ID: "runetfreedom", Name: "runetfreedom (Россия)",
		Geosite: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
		Geoip:   "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
		Note:    "ru-blocked, category-ru, реклама; нужен для пресетов маршрутизации"},
	{ID: "loyalsoldier", Name: "Loyalsoldier",
		Geosite: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
		Geoip:   "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
		Note:    "популярный набор Xray; категорий ru-blocked в нём нет"},
	{ID: "v2fly", Name: "v2fly (официальный)",
		Geosite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
		Geoip:   "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
		Note:    "исходные списки v2fly"},
}

// ParseInterval accepts "24h", "12h", "off"/"0" (disabled). Empty means 24h.
func ParseInterval(s string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return 24 * time.Hour, nil
	case "off", "0", "never":
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("geo update interval %q: %w", s, err)
	}
	if d < time.Hour {
		return 0, fmt.Errorf("geo update interval %q: at least 1h", s)
	}
	return d, nil
}

var client = &http.Client{Timeout: 5 * time.Minute}

// Download fetches url into path atomically.
func Download(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cypher")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s: empty file", url)
	}
	os.Chmod(tmp.Name(), 0o644)
	return os.Rename(tmp.Name(), path)
}

// EnsureAll downloads sources whose file is missing.
func EnsureAll(ctx context.Context, srcs []Source) error {
	var errs []error
	for _, s := range srcs {
		if s.URL == "" {
			continue
		}
		if st, err := os.Stat(s.Path); err == nil && st.Size() > 0 {
			continue
		}
		slog.Info("downloading", "file", filepath.Base(s.Path), "url", s.URL)
		if err := Download(ctx, s.URL, s.Path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// UpdateAll downloads every source.
func UpdateAll(ctx context.Context, srcs []Source) error {
	var errs []error
	for _, s := range srcs {
		if s.URL == "" {
			continue
		}
		if err := Download(ctx, s.URL, s.Path); err != nil {
			errs = append(errs, err)
		} else {
			slog.Info("geo file updated", "file", filepath.Base(s.Path))
		}
	}
	return errors.Join(errs...)
}

// Run refreshes the sources every interval (based on file age, so restarts
// do not cause extra downloads) until ctx is cancelled.
func Run(ctx context.Context, srcs []Source, interval time.Duration) {
	if interval <= 0 || len(srcs) == 0 {
		return
	}
	check := time.NewTicker(min(interval/4, time.Hour))
	defer check.Stop()
	for {
		oldest := time.Now()
		for _, s := range srcs {
			if st, err := os.Stat(s.Path); err != nil {
				oldest = time.Time{}
			} else if st.ModTime().Before(oldest) {
				oldest = st.ModTime()
			}
		}
		if time.Since(oldest) >= interval {
			uctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			if err := UpdateAll(uctx, srcs); err != nil {
				slog.Warn("geo update failed, will retry", "err", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-check.C:
		}
	}
}

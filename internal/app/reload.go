package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/router"
)

// reloadInterval is how often watched files are checked for changes.
var reloadInterval = 3 * time.Second

// buildRouter compiles the routing section of cfg and returns the files it
// depends on (the config file and the geo files actually used).
func (c *Client) buildRouter(cfg *config.Config) (*router.Router, []string, error) {
	rc := cfg.Routing
	geosite, geoip := rc.Geosite, rc.Geoip
	if geosite == "" {
		geosite = "geosite.dat"
	}
	if geoip == "" {
		geoip = "geoip.dat"
	}
	geo := router.NewGeoLoader(cfg.Resolve(geosite), cfg.Resolve(geoip))
	r, err := router.New(rc, cfg.Outbounds[0].Tag, geo)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range append([]string{r.DefaultTag()}, r.OutboundTags()...) {
		if _, ok := c.outbounds[t]; !ok {
			return nil, nil, fmt.Errorf("routing refers to unknown outbound %q", t)
		}
	}
	watched := geo.UsedFiles()
	if cfg.Path != "" {
		watched = append(watched, cfg.Path)
	}
	return r, watched, nil
}

// Reload re-reads the config file's routing section and the geo files and
// atomically swaps in the new router. On error the current router is kept.
// Changes to inbounds and outbounds still require a restart.
func (c *Client) Reload() error {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	cfg := c.cfg
	if cfg.Path != "" {
		fresh, err := config.Load(cfg.Path)
		if err != nil {
			return err
		}
		// Only routing is reloaded; outbounds stay as they were started.
		fresh.Outbounds = cfg.Outbounds
		cfg = fresh
	}
	r, watched, err := c.buildRouter(cfg)
	if err != nil {
		return err
	}
	c.router.Store(r)
	c.watched = watched
	return nil
}

type fileState struct {
	mod  time.Time
	size int64
	ok   bool
}

func stat(path string) fileState {
	st, err := os.Stat(path)
	if err != nil {
		return fileState{}
	}
	return fileState{mod: st.ModTime(), size: st.Size(), ok: true}
}

func snapshot(files []string) map[string]fileState {
	m := make(map[string]fileState, len(files))
	for _, f := range files {
		m[f] = stat(f)
	}
	return m
}

func equal(a, b map[string]fileState) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// watch polls the watched files. A reload happens once a change has been
// stable for one interval, so a file that is still being downloaded is not
// picked up half-written.
func (c *Client) watchedFiles() []string {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	return c.watched
}

func (c *Client) watch(ctx context.Context, interval time.Duration) {
	applied := snapshot(c.watchedFiles())
	var pending map[string]fileState
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := snapshot(c.watchedFiles())
		if equal(cur, applied) {
			pending = nil
			continue
		}
		if pending == nil || !equal(cur, pending) {
			pending = cur // changed; wait one more interval for it to settle
			continue
		}
		start := time.Now()
		if err := c.Reload(); err != nil {
			slog.Error("routing reload failed, keeping the previous rules", "err", err)
		} else {
			slog.Info("routing reloaded", "took", time.Since(start).Round(time.Millisecond))
		}
		// Either way, do not retry until the files change again.
		applied, pending = snapshot(c.watchedFiles()), nil
	}
}

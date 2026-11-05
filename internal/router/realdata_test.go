package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
)

// TestRealGeoFiles runs against real Xray geosite.dat/geoip.dat when
// CYPHER_GEO_DIR points at a directory containing them.
func TestRealGeoFiles(t *testing.T) {
	dir := os.Getenv("CYPHER_GEO_DIR")
	if dir == "" {
		t.Skip("CYPHER_GEO_DIR not set")
	}
	start := time.Now()
	r, err := New(config.RoutingConfig{Rules: []config.RuleConfig{
		{Domain: []string{"geosite:category-ads-all"}, Outbound: "block"},
		{Domain: []string{"geosite:google", "geosite:youtube"}, Outbound: "proxy"},
		{Domain: []string{"geosite:category-ru"}, Outbound: "direct"},
		{IP: []string{"geoip:private", "geoip:ru"}, Outbound: "direct"},
	}}, "proxy", NewGeoLoader(filepath.Join(dir, "geosite.dat"), filepath.Join(dir, "geoip.dat")))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("compiled in %v", time.Since(start))
	for host, want := range map[string]string{
		"www.youtube.com": "proxy",
		"yandex.ru":       "direct",
		"77.88.55.88":     "direct", // Yandex
		"192.168.1.1":     "direct",
		"1.1.1.1":         "proxy",
	} {
		if got := r.Route(context.Background(), Metadata{Dest: dest(host, 443)}); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

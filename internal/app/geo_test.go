package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/router"
	"google.golang.org/protobuf/encoding/protowire"
)

func pb(num protowire.Number, v []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), v)
}

// TestClientDownloadsGeo starts a client whose geo files do not exist yet:
// they must be downloaded from the configured URLs before rules compile.
func TestClientDownloadsGeo(t *testing.T) {
	domain := append(protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2), pb(2, []byte("example.org"))...)
	site := pb(1, append(pb(1, []byte("TEST")), pb(2, domain)...))
	cidr := append(pb(1, []byte{10, 0, 0, 0}), protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 8)...)
	ip := pb(1, append(pb(1, []byte("LAN")), pb(2, cidr)...))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/site":
			w.Write(site)
		case "/ip":
			w.Write(ip)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		Dir:       dir,
		Inbounds:  []config.InboundConfig{{Tag: "socks", Type: "socks", Listen: freePort(t)}},
		Outbounds: []config.OutboundConfig{{Tag: "direct", Type: "direct"}, {Tag: "block", Type: "block"}},
		Routing: config.RoutingConfig{
			GeositeURL: srv.URL + "/site", GeoipURL: srv.URL + "/ip",
			Rules: []config.RuleConfig{
				{Domain: []string{"geosite:test"}, Outbound: "block"},
				{IP: []string{"geoip:lan"}, Outbound: "block"},
			},
		},
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"www.example.org": "block", "10.1.2.3": "block", "example.com": "direct"} {
		got := c.router.Load().Route(context.Background(), router.Metadata{Dest: netx.Destination{Network: "tcp", Host: host, Port: 443}})
		if got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
	}
	if _, err := filepath.Glob(filepath.Join(dir, "*.dat")); err != nil {
		t.Fatal(err)
	}

	// A broken URL with no file on disk is a clear startup error.
	cfg2 := *cfg
	cfg2.Dir = t.TempDir()
	cfg2.Routing.GeositeURL = srv.URL + "/missing"
	if _, err := NewClient(&cfg2); err == nil {
		t.Fatal("client started without its geo file")
	}
}

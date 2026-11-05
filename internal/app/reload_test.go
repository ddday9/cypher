package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/router"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func route(c *Client, host string) string {
	return c.router.Load().Route(context.Background(), router.Metadata{
		Dest: netx.Destination{Network: "tcp", Host: host, Port: 443}})
}

func TestLiveReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	cfg := map[string]any{
		"inbounds":  []map[string]any{{"type": "socks", "listen": freePort(t)}},
		"outbounds": []map[string]any{{"tag": "direct", "type": "direct"}, {"tag": "block", "type": "block"}},
		"routing": map[string]any{"rules": []map[string]any{
			{"domain": []string{"domain:a.test"}, "outbound": "block"},
		}},
	}
	writeJSON(t, path, cfg)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(loaded)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.watch(ctx, 20*time.Millisecond)

	if got := route(c, "a.test"); got != "block" {
		t.Fatalf("before reload: %s", got)
	}

	// Change the rules: the new ones must take effect without a restart.
	cfg["routing"] = map[string]any{"rules": []map[string]any{
		{"domain": []string{"domain:b.test"}, "outbound": "block"},
	}}
	time.Sleep(10 * time.Millisecond) // make sure the mtime differs
	writeJSON(t, path, cfg)
	waitFor(t, func() bool { return route(c, "b.test") == "block" && route(c, "a.test") == "direct" })

	// A broken config must keep the previous rules.
	os.WriteFile(path, []byte("{broken"), 0o644)
	time.Sleep(200 * time.Millisecond)
	if route(c, "b.test") != "block" {
		t.Fatal("broken config replaced working rules")
	}
	// Unknown outbound tag is rejected too.
	cfg["routing"] = map[string]any{"rules": []map[string]any{
		{"domain": []string{"domain:c.test"}, "outbound": "nope"},
	}}
	writeJSON(t, path, cfg)
	time.Sleep(200 * time.Millisecond)
	if route(c, "b.test") != "block" {
		t.Fatal("invalid config replaced working rules")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

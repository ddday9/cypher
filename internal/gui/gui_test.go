package gui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ddday9/cypher/internal/app"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/protocol"
)

func newTestServer(t *testing.T) (*App, *Server) {
	t.Helper()
	a, err := NewApp(t.TempDir(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(a, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return a, s
}

func call(t *testing.T, s *Server, path, token, host string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	method := http.MethodGet
	if body != nil {
		b, _ := json.Marshal(body)
		r, method = bytes.NewReader(b), http.MethodPost
	}
	req, _ := http.NewRequest(method, "http://"+s.Addr()+"/api/"+path, r)
	if host != "" {
		req.Host = host
	}
	req.Header.Set("X-Cypher-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAPIGuard(t *testing.T) {
	_, s := newTestServer(t)
	if code, _ := call(t, s, "state", "", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := call(t, s, "state", s.Token(), "evil.example:80", nil); code != http.StatusForbidden {
		t.Fatalf("foreign host: %d", code)
	}
	if code, _ := call(t, s, "state", s.Token(), "", nil); code != http.StatusOK {
		t.Fatalf("valid: %d", code)
	}
	// The page itself is served without a token (it holds no secrets).
	resp, err := http.Get("http://" + s.Addr() + "/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("index: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestImportSelectAndConfig(t *testing.T) {
	a, s := newTestServer(t)
	l1 := links.Format(links.Link{Name: "one", Server: "one.example:443", Key: protocol.GenerateKey().String()})
	l2 := links.Format(links.Link{Name: "two", Server: "two.example:443", Key: protocol.GenerateKey().String(), Fingerprint: "chrome"})
	code, out := call(t, s, "import", s.Token(), "", map[string]string{"text": l1 + "\n" + l2})
	if code != 200 || out["added"].(float64) != 2 {
		t.Fatalf("import: %d %v", code, out)
	}
	st := a.store.Get()
	if len(st.Profiles) != 2 || st.Selected != st.Profiles[0].ID {
		t.Fatalf("state after import: %+v", st)
	}
	if code, _ := call(t, s, "select", s.Token(), "", map[string]string{"id": st.Profiles[1].ID}); code != 200 {
		t.Fatalf("select: %d", code)
	}
	if code, out := call(t, s, "import", s.Token(), "", map[string]string{"text": "vless://nope"}); code != 400 || !strings.Contains(out["error"].(string), "cypher://") {
		t.Fatalf("bad import: %d %v", code, out)
	}

	// Every preset (except custom with no rules) must produce a config the
	// client accepts. Geo rules need files, so test the geo-free preset and
	// a custom one.
	p := a.store.Get().Profiles[1]
	set := a.Settings()
	set.Routing = "custom"
	set.SocksPort, set.HTTPPort = 0, 0
	cfg := a.BuildConfig(p, set)
	cfg.Inbounds[0].Listen, cfg.Inbounds[1].Listen = "127.0.0.1:0", "127.0.0.1:0"
	if _, err := app.NewClient(cfg); err != nil {
		t.Fatalf("custom config rejected: %v", err)
	}
	if cfg.Outbounds[0].Fingerprint != "chrome" {
		t.Fatalf("profile fingerprint lost: %q", cfg.Outbounds[0].Fingerprint)
	}
	set.Fingerprint = "safari"
	if a.BuildConfig(p, set).Outbounds[0].Fingerprint != "safari" {
		t.Fatal("settings fingerprint does not override")
	}
	set.Mode = "tun"
	if cfg := a.BuildConfig(p, set); cfg.Inbounds[0].Type != "tun" {
		t.Fatalf("tun mode inbounds: %+v", cfg.Inbounds)
	}
}

func TestSettingsValidation(t *testing.T) {
	a, s := newTestServer(t)
	set := a.Settings()
	set.HTTPPort = set.SocksPort
	if code, _ := call(t, s, "settings", s.Token(), "", set); code != 400 {
		t.Fatal("equal ports accepted")
	}
	set = a.Settings()
	set.Routing = "custom"
	set.CustomRules = nil
	set.CustomRules = append(set.CustomRules, Presets[0].Rules[0])
	set.CustomRules[0].Outbound = "somewhere"
	if code, _ := call(t, s, "settings", s.Token(), "", set); code != 400 {
		t.Fatal("bad outbound accepted")
	}
	set.CustomRules[0].Outbound = "block"
	if code, out := call(t, s, "settings", s.Token(), "", set); code != 200 {
		t.Fatalf("valid settings rejected: %v", out)
	}
	if a.Settings().Routing != "custom" {
		t.Fatal("settings not saved")
	}
}

func TestConnectWithoutServer(t *testing.T) {
	a, _ := newTestServer(t)
	if err := a.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "добавьте сервер") {
		t.Fatalf("got %v", err)
	}
}

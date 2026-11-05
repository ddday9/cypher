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
	if cfg.Outbounds[0].Fingerprint != "firefox" {
		t.Fatalf("default fingerprint is %q, want firefox even if the link says chrome", cfg.Outbounds[0].Fingerprint)
	}
	set.Fingerprint = "link"
	if fp := a.BuildConfig(p, set).Outbounds[0].Fingerprint; fp != "chrome" {
		t.Fatalf("link fingerprint not used: %q", fp)
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

func TestUserRules(t *testing.T) {
	s := defaultSettings()
	s.Routing = "smart"
	s.UserRules = []UserRule{
		{Type: "domain", Value: "example.org, Example.NET", Action: "block"},
		{Type: "process", Value: "dota2.exe, C:\\Games\\My Game\\game.exe", Action: "direct"},
		{Type: "port", Value: "27015-27030 3478", Action: "direct"},
	}
	rules, def, err := routingRules(s)
	if err != nil {
		t.Fatal(err)
	}
	if def != "proxy" {
		t.Fatalf("default %q", def)
	}
	// Application rules come first, then user rules, then the preset.
	if len(rules[0].Process) != 2 || rules[0].Process[1] != `C:\Games\My Game\game.exe` {
		t.Fatalf("first rule: %+v", rules[0])
	}
	if got := rules[1].Domain; len(got) != 2 || got[1] != "domain:example.net" {
		t.Fatalf("domain rule: %+v", rules[1])
	}
	if rules[2].Port != "27015-27030,3478" {
		t.Fatalf("port rule: %+v", rules[2])
	}
	if len(rules) != 3+len(Presets[0].Rules) {
		t.Fatalf("preset rules not appended: %d", len(rules))
	}
	s.Routing, s.DefaultAction = "custom", "direct"
	if rules, def, _ := routingRules(s); len(rules) != 3 || def != "direct" {
		t.Fatalf("custom: %d rules, default %q", len(rules), def)
	}
	for _, bad := range []UserRule{{Type: "x", Value: "1", Action: "direct"}, {Type: "ip", Value: "", Action: "direct"}, {Type: "ip", Value: "1.1.1.1", Action: "nowhere"}} {
		if _, _, err := routingRules(Settings{UserRules: []UserRule{bad}}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	a, _ := newTestServer(t)
	bad, _, _ := routingRules(Settings{Routing: "custom", UserRules: []UserRule{{Type: "ip", Value: "300.1.1.1", Action: "direct"}}})
	if err := a.compileRules(bad); err == nil || !strings.Contains(err.Error(), "неверный IP") {
		t.Fatalf("compile: %v", err)
	}
	// Geo rules are skipped without geo files, the rest is still checked.
	geoOnly, _, _ := routingRules(Settings{Routing: "custom", UserRules: []UserRule{{Type: "geosite", Value: "google", Action: "proxy"}}})
	if err := a.compileRules(geoOnly); err != nil {
		t.Fatalf("geo rule without files: %v", err)
	}
}

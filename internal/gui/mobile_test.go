package gui

import (
	"encoding/json"
	"io"
	"slices"
	"testing"
)

type fakeMobile struct {
	opened []string
	closed int
	fd     int
}

func (f *fakeMobile) OpenTUN(s string) (int, error) { f.opened = append(f.opened, s); return f.fd, nil }
func (f *fakeMobile) CloseTUN()                     { f.closed++ }
func (f *fakeMobile) KeepAlive(bool)                {}
func (f *fakeMobile) Apps() string {
	return `[{"name":"org.telegram.messenger","label":"Telegram"},{"name":"ru.sberbankmobile","label":"СберБанк"}]`
}

func TestMobile(t *testing.T) {
	f := &fakeMobile{fd: 42}
	SetMobile(f)
	defer SetMobile(nil)
	a, err := NewApp(t.TempDir(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s := a.Settings()
	if s.Mode != "tun" || !s.HideRuApps || s.ProxyPort < 20000 || s.ProxyUser == "" || s.ProxyPass == "" {
		t.Fatalf("android defaults: %+v", s)
	}

	// VPN mode: a TUN from the system, no local listeners at all.
	s.UserRules = []UserRule{{Type: "process", Value: "com.example.bank", Action: "direct"},
		{Type: "process", Value: "org.telegram.messenger", Action: "proxy"}}
	in, err := mobileInbounds(f, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 1 || in[0].Type != "tun" || in[0].FD != 42 || in[0].Listen != "" {
		t.Fatalf("vpn inbounds: %+v", in)
	}
	var vs VPNSettings
	json.Unmarshal([]byte(f.opened[0]), &vs)
	if !slices.Contains(vs.Disallowed, "com.example.bank") || !slices.Contains(vs.Disallowed, "ru.sberbankmobile") || len(vs.Allowed) != 0 {
		t.Fatalf("excluded apps: %+v", vs)
	}
	// Only selected apps in the VPN.
	s.AppScope = "selected"
	if v := mobileVPN(s); !slices.Equal(v.Allowed, []string{"org.telegram.messenger"}) || len(v.Disallowed) != 0 {
		t.Fatalf("selected apps: %+v", v)
	}

	// Proxy mode: SOCKS5 with a password on the random port.
	s.Mode = "proxy"
	in, _ = mobileInbounds(f, s)
	if len(in) != 1 || in[0].Type != "socks" || in[0].Username == "" || in[0].Password == "" {
		t.Fatalf("proxy inbounds: %+v", in)
	}

	// The UI talks to the API in process.
	srv := NewInProcessServer(a, "test")
	code, body := srv.Call("GET", "/api/info", nil)
	var info Info
	if code != 200 || json.Unmarshal(body, &info) != nil || !info.Mobile || len(info.RussianApps) == 0 {
		t.Fatalf("info: %d %s", code, body)
	}
	if code, body = srv.Call("GET", "/api/processes", nil); code != 200 || !json.Valid(body) {
		t.Fatalf("apps: %d %s", code, body)
	}
	if len(Asset("index.html")) == 0 || len(Asset("app.js")) == 0 || Asset("nope") != nil {
		t.Fatal("assets")
	}
}

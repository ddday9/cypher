package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/engine"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/sysproxy"
)

// ErrNeedElevation means TUN mode needs administrator rights.
var ErrNeedElevation = errors.New("для режима TUN нужны права администратора")

// App is the desktop client backend.
type App struct {
	dir    string
	store  *Store
	engine *engine.Engine
	Logs   *engine.LogBuffer
	http   *http.Client

	mu        sync.Mutex
	busy      string
	proxySave *sysproxy.Saved
	geoMu     sync.Mutex
	pings     map[string]int // profile ID → ms (-1 = failed)
	activeID  string
	mode      string
}

// NewApp opens the state in dir and prepares logging.
func NewApp(dir string, logOut io.Writer) (*App, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	a := &App{
		dir: dir, store: store, engine: engine.New(),
		Logs:  engine.NewLogBuffer(2000, logOut),
		http:  &http.Client{Timeout: 5 * time.Minute},
		pings: map[string]int{},
	}
	a.setLogLevel(store.Get().Settings.LogLevel)
	a.recoverSystemProxy()
	return a, nil
}

func (a *App) setLogLevel(level string) {
	l := slog.LevelInfo
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(a.Logs, &slog.HandlerOptions{Level: l})))
}

// Background starts periodic jobs (geo updates, an initial ping).
func (a *App) Background(ctx context.Context) {
	go a.geoLoop(ctx)
	go a.PingAll(ctx)
}

func (a *App) setBusy(s string) {
	a.mu.Lock()
	a.busy = s
	a.mu.Unlock()
}

// --- system proxy, with recovery after a crash ---------------------------

func (a *App) proxyMarker() string { return filepath.Join(a.dir, "sysproxy.json") }

func (a *App) enableSystemProxy(addr string) error {
	prev, err := sysproxy.Enable(addr)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(prev)
	os.WriteFile(a.proxyMarker(), b, 0o600)
	a.mu.Lock()
	a.proxySave = prev
	a.mu.Unlock()
	return nil
}

func (a *App) restoreSystemProxy() {
	a.mu.Lock()
	prev := a.proxySave
	a.proxySave = nil
	a.mu.Unlock()
	if prev == nil {
		return
	}
	if err := sysproxy.Restore(prev); err != nil {
		slog.Warn("restore system proxy", "err", err)
	}
	os.Remove(a.proxyMarker())
}

// recoverSystemProxy restores the proxy setting if the previous run did not
// exit cleanly (otherwise the browser would point at a dead port).
func (a *App) recoverSystemProxy() {
	b, err := os.ReadFile(a.proxyMarker())
	if err != nil {
		return
	}
	var prev sysproxy.Saved
	if json.Unmarshal(b, &prev) == nil {
		sysproxy.Restore(&prev)
		slog.Info("system proxy restored after an unclean exit")
	}
	os.Remove(a.proxyMarker())
}

// --- connect ---------------------------------------------------------------

func (a *App) selected(st State) (Profile, error) {
	for _, p := range st.Profiles {
		if p.ID == st.Selected {
			return p, nil
		}
	}
	if len(st.Profiles) > 0 {
		return st.Profiles[0], nil
	}
	return Profile{}, errors.New("добавьте сервер: вставьте ссылку cypher:// или подписку")
}

// BuildConfig turns a profile and settings into a client configuration.
func (a *App) BuildConfig(p Profile, s Settings) *config.Config {
	fp := p.Fingerprint
	if s.Fingerprint != "" {
		fp = s.Fingerprint
	}
	cfg := &config.Config{Dir: a.dir}
	cfg.Log.Level = s.LogLevel
	socks := config.InboundConfig{Tag: "socks", Type: "socks", Listen: "127.0.0.1:" + strconv.Itoa(s.SocksPort)}
	if s.Mode == "tun" {
		cfg.Inbounds = []config.InboundConfig{{Tag: "tun", Type: "tun", Name: "cypher"}, socks}
	} else {
		cfg.Inbounds = []config.InboundConfig{socks,
			{Tag: "http", Type: "http", Listen: "127.0.0.1:" + strconv.Itoa(s.HTTPPort)}}
	}
	cfg.Outbounds = []config.OutboundConfig{
		{Tag: "proxy", Type: "cypher", Server: p.Server, ServerName: p.ServerName, Key: p.Key,
			Fingerprint: fp, Connections: p.Connections},
		{Tag: "direct", Type: "direct"},
		{Tag: "block", Type: "block"},
	}
	preset := presetByID(s.Routing)
	rules := preset.Rules
	if preset.ID == "custom" {
		rules = s.CustomRules
	}
	cfg.Routing = config.RoutingConfig{
		Geosite: a.geoPath(geositeFile), Geoip: a.geoPath(geoipFile),
		Rules: rules, Default: preset.Default,
	}
	return cfg
}

func needsGeo(rules []config.RuleConfig) bool {
	for _, r := range rules {
		for _, d := range r.Domain {
			if strings.HasPrefix(d, "geosite:") {
				return true
			}
		}
		for _, ip := range r.IP {
			if strings.HasPrefix(ip, "geoip:") {
				return true
			}
		}
	}
	return false
}

// Connect starts the client with the selected profile.
func (a *App) Connect(ctx context.Context) error {
	st := a.store.Get()
	p, err := a.selected(st)
	if err != nil {
		return err
	}
	s := st.Settings
	if s.Mode == "tun" && !isElevated() {
		return ErrNeedElevation
	}
	cfg := a.BuildConfig(p, s)
	if needsGeo(cfg.Routing.Rules) && !a.haveGeo() {
		if err := a.UpdateGeo(ctx); err != nil {
			return fmt.Errorf("%w (без баз geosite/geoip правила маршрутизации не работают; можно выбрать «Всё через VPN»)", err)
		}
	}
	a.restoreSystemProxy()
	a.setBusy("Подключаюсь…")
	defer a.setBusy("")
	if err := a.engine.Start(cfg); err != nil {
		return humanError(err)
	}
	if s.Mode != "tun" && s.SystemProxy {
		if err := a.enableSystemProxy("127.0.0.1:" + strconv.Itoa(s.HTTPPort)); err != nil && !errors.Is(err, sysproxy.ErrUnsupported) {
			slog.Warn("system proxy", "err", err)
		}
	}
	a.mu.Lock()
	a.activeID, a.mode = p.ID, s.Mode
	a.mu.Unlock()
	return nil
}

// humanError turns common failures into something actionable.
func humanError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "address already in use"), strings.Contains(msg, "Only one usage of each socket address"):
		return fmt.Errorf("порт уже занят другой программой — смените порты в настройках (%w)", err)
	case strings.Contains(msg, "wintun"):
		return fmt.Errorf("не удалось создать адаптер TUN (%w)", err)
	}
	return err
}

// Disconnect stops the client and restores the system proxy.
func (a *App) Disconnect() {
	a.engine.Stop()
	a.restoreSystemProxy()
	a.mu.Lock()
	a.activeID = ""
	a.mu.Unlock()
}

// Reconnect applies changed settings if connected.
func (a *App) Reconnect(ctx context.Context) error {
	if a.engine.State().Status != engine.StatusConnected {
		return nil
	}
	return a.Connect(ctx)
}

// Shutdown is called on exit.
func (a *App) Shutdown() { a.Disconnect() }

// --- profiles and subscriptions --------------------------------------------

// Import adds profiles from text: links, a base64 list, or a subscription URL.
func (a *App) Import(ctx context.Context, text string) (int, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") {
		sub := Subscription{ID: newID(), URL: text, Name: subName(text)}
		if err := a.store.Update(func(s *State) error {
			for _, ex := range s.Subscriptions {
				if ex.URL == text {
					return errors.New("эта подписка уже добавлена")
				}
			}
			s.Subscriptions = append(s.Subscriptions, sub)
			return nil
		}); err != nil {
			return 0, err
		}
		return a.RefreshSubscription(ctx, sub.ID)
	}
	ls, errs := links.ParseList(text)
	if len(ls) == 0 {
		if len(errs) > 0 {
			return 0, fmt.Errorf("ссылка не распознана: %v", errs[0])
		}
		return 0, errors.New("не найдено ни одной ссылки cypher://")
	}
	err := a.store.Update(func(s *State) error {
		for _, l := range ls {
			s.Profiles = append(s.Profiles, Profile{ID: newID(), Link: l})
		}
		if s.Selected == "" {
			s.Selected = s.Profiles[0].ID
		}
		return nil
	})
	go a.PingAll(context.Background())
	return len(ls), err
}

func subName(u string) string {
	if pu, err := http.NewRequest(http.MethodGet, u, nil); err == nil {
		return pu.URL.Host
	}
	return u
}

// RefreshSubscription re-downloads one subscription and replaces its profiles.
func (a *App) RefreshSubscription(ctx context.Context, id string) (int, error) {
	st := a.store.Get()
	var sub *Subscription
	for i := range st.Subscriptions {
		if st.Subscriptions[i].ID == id {
			sub = &st.Subscriptions[i]
		}
	}
	if sub == nil {
		return 0, errors.New("подписка не найдена")
	}
	ls, ferr := a.fetchSubscription(ctx, sub.URL)
	err := a.store.Update(func(s *State) error {
		for i := range s.Subscriptions {
			if s.Subscriptions[i].ID != id {
				continue
			}
			if ferr != nil {
				s.Subscriptions[i].Error = ferr.Error()
				return nil
			}
			s.Subscriptions[i].Error = ""
			s.Subscriptions[i].Updated = time.Now()
		}
		if ferr != nil {
			return nil
		}
		// Keep the selection if the same server is still there.
		var selKey string
		for _, p := range s.Profiles {
			if p.ID == s.Selected {
				selKey = p.Server + p.Key
			}
		}
		kept := s.Profiles[:0]
		for _, p := range s.Profiles {
			if p.SubID != id {
				kept = append(kept, p)
			}
		}
		s.Profiles = kept
		for _, l := range ls {
			p := Profile{ID: newID(), SubID: id, Link: l}
			if p.Server+p.Key == selKey {
				s.Selected = p.ID
			}
			s.Profiles = append(s.Profiles, p)
		}
		if s.Selected == "" && len(s.Profiles) > 0 {
			s.Selected = s.Profiles[0].ID
		}
		return nil
	})
	if ferr != nil {
		return 0, ferr
	}
	return len(ls), err
}

func (a *App) fetchSubscription(ctx context.Context, url string) ([]links.Link, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cypher")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	ls, _ := links.ParseList(string(body))
	if len(ls) == 0 {
		return nil, errors.New("в подписке нет ссылок cypher://")
	}
	return ls, nil
}

// --- ping ------------------------------------------------------------------

// PingAll measures TCP connect time to every server.
func (a *App) PingAll(ctx context.Context) map[string]int {
	st := a.store.Get()
	res := make(map[string]int, len(st.Profiles))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, p := range st.Profiles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms := ping(ctx, p.Server)
			mu.Lock()
			res[p.ID] = ms
			mu.Unlock()
		}()
	}
	wg.Wait()
	a.mu.Lock()
	a.pings = res
	a.mu.Unlock()
	return res
}

func ping(ctx context.Context, server string) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	c, err := netx.NewDialer(5*time.Second).DialContext(ctx, "tcp", server)
	if err != nil {
		return -1
	}
	c.Close()
	return int(time.Since(start).Milliseconds())
}

// --- misc ------------------------------------------------------------------

// Info is static information for the UI.
type Info struct {
	Version  string   `json:"version"`
	OS       string   `json:"os"`
	Elevated bool     `json:"elevated"`
	DataDir  string   `json:"dataDir"`
	Presets  []Preset `json:"presets"`
}

func (a *App) Info(version string) Info {
	return Info{Version: version, OS: runtime.GOOS, Elevated: isElevated(), DataDir: a.dir, Presets: Presets}
}

// localAddr reports whether a TCP port on 127.0.0.1 is free.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// validateRules compiles routing rules without geo files being required to
// exist for non-geo rules.
func validateRules(rc config.RoutingConfig) error {
	for i, r := range rc.Rules {
		switch r.Outbound {
		case "proxy", "direct", "block":
		default:
			return fmt.Errorf("правило %d: outbound должен быть proxy, direct или block", i+1)
		}
		if len(r.Domain) == 0 && len(r.IP) == 0 && r.Port == "" && r.Network == "" {
			return fmt.Errorf("правило %d: нет условий", i+1)
		}
	}
	return nil
}

// Connected reports whether the client is running.
func (a *App) Connected() bool { return a.engine.State().Status == engine.StatusConnected }

// Toggle connects or disconnects (used by the tray menu).
func (a *App) Toggle(ctx context.Context) error {
	if a.Connected() {
		a.Disconnect()
		return nil
	}
	return a.Connect(ctx)
}

// Settings returns the current settings.
func (a *App) Settings() Settings { return a.store.Get().Settings }

// SetMode switches between "proxy" and "tun".
func (a *App) SetMode(mode string) error {
	return a.store.Update(func(s *State) error { s.Settings.Mode = mode; return nil })
}

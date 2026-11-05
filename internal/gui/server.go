package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/engine"
	"github.com/ddday9/cypher/internal/geo"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/procinfo"
)

//go:embed web
var webFS embed.FS

// Server is the local API and web UI, bound to 127.0.0.1 only.
type Server struct {
	app     *App
	version string
	token   string
	ln      net.Listener
	srv     *http.Server

	// OnShow is called when another instance asks this one to show its window.
	OnShow func()
	// OnQuit is called when the UI asks the application to exit.
	OnQuit func()
}

// NewServer listens on a random local port.
func NewServer(app *App, version string) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var t [16]byte
	rand.Read(t[:])
	s := &Server{app: app, version: version, token: hex.EncodeToString(t[:]), ln: ln}
	s.srv = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln)
	return s, nil
}

// URL opens the UI; the token travels in the fragment, never in requests.
func (s *Server) URL() string { return "http://" + s.ln.Addr().String() + "/#" + s.token }

// Addr and Token let a second instance reach this one.
func (s *Server) Addr() string  { return s.ln.Addr().String() }
func (s *Server) Token() string { return s.token }

func (s *Server) Close() { s.srv.Close() }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	api := map[string]http.HandlerFunc{
		"GET /api/info":                  s.info,
		"GET /api/state":                 s.state,
		"POST /api/connect":              s.connect,
		"POST /api/disconnect":           s.disconnect,
		"POST /api/import":               s.importLinks,
		"POST /api/select":               s.selectProfile,
		"POST /api/profile/delete":       s.deleteProfile,
		"POST /api/profile/share":        s.shareProfile,
		"POST /api/subscription/refresh": s.refreshSub,
		"POST /api/subscription/delete":  s.deleteSub,
		"POST /api/ping":                 s.ping,
		"POST /api/settings":             s.saveSettings,
		"POST /api/geo/update":           s.updateGeo,
		"GET /api/processes":             s.processes,
		"GET /api/logs":                  s.logs,
		"POST /api/elevate":              s.elevate,
		"POST /api/show":                 s.show,
		"POST /api/quit":                 s.quit,
	}
	for pattern, h := range api {
		mux.Handle(pattern, s.guard(h))
	}
	return mux
}

// guard rejects requests without the token or with a foreign Host header
// (DNS rebinding). The token is sent in a custom header, which a web page
// from another origin cannot add without a CORS preflight we never allow.
func (s *Server) guard(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.ln.Addr().String() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Cypher-Token")), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	code := ""
	if errors.Is(err, ErrNeedElevation) {
		code = "need_elevation"
	}
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "code": code})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.app.Info(s.version))
}

// UIState is what the interface polls every second.
type UIState struct {
	engine.State
	Busy     string         `json:"busy,omitempty"`
	ActiveID string         `json:"activeId,omitempty"`
	Mode     string         `json:"mode,omitempty"`
	Pings    map[string]int `json:"pings"`
	Data     State          `json:"data"`
	HaveGeo  bool           `json:"haveGeo"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	a := s.app
	a.mu.Lock()
	st := UIState{Busy: a.busy, ActiveID: a.activeID, Mode: a.mode, Pings: map[string]int{}}
	for k, v := range a.pings {
		st.Pings[k] = v
	}
	a.mu.Unlock()
	st.State = a.engine.State()
	if st.Status != engine.StatusConnected {
		st.ActiveID, st.Mode = "", ""
	}
	if st.Busy != "" && st.Status == engine.StatusStopped {
		st.Status = engine.StatusConnecting
	}
	st.Data = a.store.Get()
	st.HaveGeo = a.haveGeo()
	writeJSON(w, st)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Connect(r.Context()); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	s.app.Disconnect()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) importLinks(w http.ResponseWriter, r *http.Request) {
	var req struct{ Text string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	n, err := s.app.Import(r.Context(), req.Text)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]int{"added": n})
}

func (s *Server) selectProfile(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	err := s.app.store.Update(func(st *State) error {
		for _, p := range st.Profiles {
			if p.ID == req.ID {
				st.Selected = req.ID
				return nil
			}
		}
		return errors.New("сервер не найден")
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Switching servers while connected reconnects to the new one.
	if err := s.app.Reconnect(r.Context()); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	s.app.store.Update(func(st *State) error {
		kept := st.Profiles[:0]
		for _, p := range st.Profiles {
			if p.ID != req.ID {
				kept = append(kept, p)
			}
		}
		st.Profiles = kept
		if st.Selected == req.ID {
			st.Selected = ""
			if len(kept) > 0 {
				st.Selected = kept[0].ID
			}
		}
		return nil
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) shareProfile(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	for _, p := range s.app.store.Get().Profiles {
		if p.ID == req.ID {
			writeJSON(w, map[string]string{"link": links.Format(p.Link)})
			return
		}
	}
	writeErr(w, errors.New("сервер не найден"))
}

func (s *Server) refreshSub(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	ids := []string{req.ID}
	if req.ID == "" {
		ids = nil
		for _, sub := range s.app.store.Get().Subscriptions {
			ids = append(ids, sub.ID)
		}
	}
	total := 0
	var lastErr error
	for _, id := range ids {
		n, err := s.app.RefreshSubscription(r.Context(), id)
		total += n
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil && total == 0 {
		writeErr(w, lastErr)
		return
	}
	writeJSON(w, map[string]int{"profiles": total})
}

func (s *Server) deleteSub(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	s.app.store.Update(func(st *State) error {
		subs := st.Subscriptions[:0]
		for _, sub := range st.Subscriptions {
			if sub.ID != req.ID {
				subs = append(subs, sub)
			}
		}
		st.Subscriptions = subs
		kept := st.Profiles[:0]
		for _, p := range st.Profiles {
			if p.SubID != req.ID {
				kept = append(kept, p)
			}
		}
		st.Profiles = kept
		return nil
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.app.PingAll(r.Context()))
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := readJSON(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	if in.Mode != "proxy" && in.Mode != "tun" {
		writeErr(w, errors.New("неизвестный режим"))
		return
	}
	if in.SocksPort < 1 || in.SocksPort > 65535 || in.HTTPPort < 1 || in.HTTPPort > 65535 || in.SocksPort == in.HTTPPort {
		writeErr(w, errors.New("порты должны быть разными числами от 1 до 65535"))
		return
	}
	rules, _, err := routingRules(in)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.app.compileRules(rules); err != nil {
		writeErr(w, err)
		return
	}
	if err := validateRules(config.RoutingConfig{Rules: in.CustomRules}); err != nil {
		writeErr(w, err)
		return
	}
	switch in.Fingerprint {
	case "", "link", "firefox", "chrome", "safari", "edge", "ios", "android", "random":
	default:
		writeErr(w, errors.New("неизвестный отпечаток TLS"))
		return
	}
	switch in.AntiFreeze {
	case "", "auto", "on", "off":
	default:
		writeErr(w, errors.New("защита от заморозки: auto, on или off"))
		return
	}
	switch in.DefaultAction {
	case "", "proxy", "direct":
	default:
		writeErr(w, errors.New("действие по умолчанию: proxy или direct"))
		return
	}
	if in.GeoSource != "custom" {
		for _, p := range geo.Presets {
			if p.ID == in.GeoSource {
				in.GeositeURL, in.GeoipURL = p.Geosite, p.Geoip
			}
		}
	}
	for _, u := range []string{in.GeositeURL, in.GeoipURL} {
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			writeErr(w, errors.New("ссылки на geosite и geoip должны начинаться с https://"))
			return
		}
	}
	if in.GeoInterval < 0 || in.GeoInterval > 24*30 {
		writeErr(w, errors.New("период обновления баз: от 1 часа до 30 дней"))
		return
	}
	var prev Settings
	err = s.app.store.Update(func(st *State) error {
		prev = st.Settings
		in.GeoUpdated = st.Settings.GeoUpdated
		st.Settings = in
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	if prev.Autostart != in.Autostart {
		if err := setAutostart(in.Autostart); err != nil {
			slog.Warn("autostart", "err", err)
		}
	}
	if prev.LogLevel != in.LogLevel {
		s.app.setLogLevel(in.LogLevel)
	}
	if (prev.GeositeURL != in.GeositeURL || prev.GeoipURL != in.GeoipURL) && s.app.haveGeo() {
		// New source: fetch now; a running client applies the files itself.
		go func() {
			if err := s.app.UpdateGeo(context.Background()); err != nil {
				slog.Warn("geo update after source change", "err", err)
			}
		}()
	}
	if err := s.app.Reconnect(context.Background()); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) updateGeo(w http.ResponseWriter, r *http.Request) {
	if err := s.app.UpdateGeo(r.Context()); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) processes(w http.ResponseWriter, r *http.Request) {
	ps, err := procinfo.List()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, ps)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	lines, next := s.app.Logs.Since(from)
	writeJSON(w, map[string]any{"lines": lines, "next": next})
}

func (s *Server) elevate(w http.ResponseWriter, r *http.Request) {
	if err := RelaunchElevated("--connect"); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	if s.OnQuit != nil {
		go func() { time.Sleep(300 * time.Millisecond); s.OnQuit() }()
	}
}

func (s *Server) show(w http.ResponseWriter, r *http.Request) {
	if s.OnShow != nil {
		s.OnShow()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) quit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"ok": true})
	if s.OnQuit != nil {
		go s.OnQuit()
	}
}

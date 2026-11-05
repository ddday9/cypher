// Package mobile is the Go side of nevio for Android, built with
// "gomobile bind" into an AAR (see android/ and the Makefile target
// "android"). The app's WebView shows the same interface as on Windows; its
// requests reach the API through Call, in process, so nevio opens no local
// port in VPN mode.
package mobile

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/ddday9/cypher/internal/gui"
)

// Platform is implemented in Kotlin.
type Platform interface {
	// OpenTUN starts the VpnService with settings (JSON) and returns the
	// TUN file descriptor (detached: Go owns and closes it), or 0 when the
	// user has not allowed the VPN yet.
	OpenTUN(settings string) (int, error)
	CloseTUN()
	// Apps returns installed apps as JSON [{"name": package, "label": name}].
	Apps() string
	// KeepAlive starts or stops the background service of the proxy mode.
	KeepAlive(on bool)
}

var (
	mu     sync.Mutex
	app    *gui.App
	server *gui.Server
	cancel context.CancelFunc
)

type platform struct{ p Platform }

func (p platform) OpenTUN(s string) (int, error) { return p.p.OpenTUN(s) }
func (p platform) CloseTUN()                     { p.p.CloseTUN() }
func (p platform) Apps() string                  { return p.p.Apps() }
func (p platform) KeepAlive(on bool)             { p.p.KeepAlive(on) }

// Start runs nevio with its data in dir. Calling it again does nothing.
func Start(dir string, p Platform, version string) error {
	mu.Lock()
	defer mu.Unlock()
	if app != nil {
		return nil
	}
	os.MkdirAll(dir, 0o700)
	gui.SetMobile(platform{p})
	a, err := gui.NewApp(dir, openLog(dir))
	if err != nil {
		return err
	}
	ctx, c := context.WithCancel(context.Background())
	a.Background(ctx)
	app, server, cancel = a, gui.NewInProcessServer(a, version), c
	slog.Info("nevio started", "version", version, "platform", "android")
	if a.Settings().AutoConnect {
		go func() {
			if err := a.Connect(ctx); err != nil {
				slog.Error("auto-connect", "err", err)
			}
		}()
	}
	return nil
}

func openLog(dir string) io.Writer {
	path := filepath.Join(dir, "nevio.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 2<<20 {
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return io.Discard
	}
	return f
}

// Call runs an API request ("GET", "/api/state", "") and returns a JSON
// envelope {"status": 200, "body": <response>}.
func Call(method, path, body string) string {
	mu.Lock()
	s := server
	mu.Unlock()
	if s == nil {
		return `{"status":503,"body":{"error":"nevio is not started"}}`
	}
	status, resp := s.Call(method, path, []byte(body))
	if !json.Valid(resp) {
		resp, _ = json.Marshal(map[string]string{"error": string(resp)})
	}
	out, _ := json.Marshal(struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}{status, resp})
	return string(out)
}

// Asset returns a file of the interface (index.html, app.js, …).
func Asset(path string) []byte { return gui.Asset(path) }

// Disconnect stops the tunnel (the VPN was revoked by the system, or the
// user turned it off from the notification).
func Disconnect() {
	mu.Lock()
	a := app
	mu.Unlock()
	if a != nil {
		a.Disconnect()
	}
}

// Connect connects with the current settings (quick settings tile).
func Connect() string {
	mu.Lock()
	a := app
	mu.Unlock()
	if a == nil {
		return "nevio is not started"
	}
	if err := a.Connect(context.Background()); err != nil {
		return err.Error()
	}
	return ""
}

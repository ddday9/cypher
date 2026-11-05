// Command cypher-gui is the desktop client: a window with the interface, a
// tray icon, and the cypher core running inside the same process.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ddday9/cypher/internal/gui"
)

var version = "dev"

type lockInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

// notifyRunning asks an already running instance to show its window.
func notifyRunning(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "gui.json"))
	if err != nil {
		return false
	}
	var li lockInfo
	if json.Unmarshal(b, &li) != nil {
		return false
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+li.Addr+"/api/show", bytes.NewReader([]byte("{}")))
	req.Header.Set("X-Cypher-Token", li.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func openLog(dir string) io.Writer {
	path := filepath.Join(dir, "cypher.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 5<<20 {
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return os.Stderr
	}
	return f
}

func main() {
	minimized := flag.Bool("minimized", false, "start in the tray without opening the window")
	connect := flag.Bool("connect", false, "connect right after start")
	browser := flag.Bool("browser", false, "open the interface in the default browser instead of a window")
	flag.Parse()

	dir := gui.DataDir()
	os.MkdirAll(dir, 0o700)

	// One instance at a time. After a relaunch with administrator rights
	// (--connect) the old instance needs a moment to exit.
	deadline := time.Now()
	if *connect {
		deadline = deadline.Add(3 * time.Second)
	}
	for notifyRunning(dir) {
		if time.Now().After(deadline) {
			return // the running instance shows its window
		}
		time.Sleep(200 * time.Millisecond)
	}

	app, err := gui.NewApp(dir, openLog(dir))
	if err != nil {
		fatal(err)
	}
	prepareWintun()
	srv, err := gui.NewServer(app, version)
	if err != nil {
		fatal(err)
	}
	li, _ := json.Marshal(lockInfo{Addr: srv.Addr(), Token: srv.Token(), PID: os.Getpid()})
	os.WriteFile(filepath.Join(dir, "gui.json"), li, 0o600)
	slog.Info("cypher-gui started", "version", version, "ui", srv.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	app.Background(ctx)
	if *connect || app.Settings().AutoConnect {
		go func() {
			if err := app.Connect(ctx); err != nil {
				slog.Error("auto-connect", "err", err)
			}
		}()
	}

	runUI(app, srv, *minimized, *browser)

	cancel()
	app.Shutdown()
	srv.Close()
	os.Remove(filepath.Join(dir, "gui.json"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cypher-gui:", err)
	showError(err.Error())
	os.Exit(1)
}

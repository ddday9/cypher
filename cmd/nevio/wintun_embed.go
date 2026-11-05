//go:build windows && wintun

package main

import (
	"bytes"
	_ "embed"
	"log/slog"
	"os"
	"path/filepath"
)

//go:embed assets/wintun.dll
var wintunDLL []byte

// prepareWintun puts the bundled wintun.dll next to the executable, where
// the TUN driver loader looks for it.
func prepareWintun() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, wintunDLL) {
		return
	}
	if err := os.WriteFile(path, wintunDLL, 0o644); err != nil {
		slog.Debug("wintun.dll not written (TUN mode will need administrator rights)", "err", err)
	}
}

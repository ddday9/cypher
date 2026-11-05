//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/ddday9/cypher/internal/gui"
)

func showError(string) {}

// runUI on Linux/macOS serves the interface in the browser (useful for
// development); Ctrl+C exits.
func runUI(_ *gui.App, srv *gui.Server, minimized, _ bool) {
	fmt.Println("nevio: open", srv.URL())
	open := func() {
		for _, cmd := range []string{"xdg-open", "open"} {
			if exec.Command(cmd, srv.URL()).Start() == nil {
				return
			}
		}
	}
	srv.OnShow = open
	quit := make(chan os.Signal, 1)
	srv.OnQuit = func() { quit <- syscall.SIGTERM }
	if !minimized {
		open()
	}
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
}

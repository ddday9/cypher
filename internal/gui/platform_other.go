//go:build !windows

package gui

import (
	"errors"
	"os"
)

func isElevated() bool { return os.Geteuid() == 0 }

// RelaunchElevated is only implemented on Windows.
func RelaunchElevated(...string) error {
	return errors.New("restart nevio as root (sudo) for TUN mode")
}

func setAutostart(bool) error { return errors.New("autostart is only supported on Windows") }

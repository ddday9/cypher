package config

import (
	"os"
	"path/filepath"
)

func dirOf(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Dir(path)
	}
	return filepath.Dir(abs)
}

// Resolve turns a relative path into one that exists: it is looked up next to
// the config file first, then next to the executable. If neither exists the
// config-relative path is returned (so the error message points there).
func (c *Config) Resolve(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	candidates := []string{filepath.Join(c.Dir, path)}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), path))
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

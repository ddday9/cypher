// Package procinfo finds which program owns a local socket, for routing
// rules by application ("dota2.exe → direct").
package procinfo

import (
	"errors"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNotFound means no process owns the socket (or it is not visible).
var ErrNotFound = errors.New("process not found")

type cacheKey struct {
	network string
	addr    netip.AddrPort
}

type cacheEntry struct {
	path string
	err  error
	at   time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[cacheKey]cacheEntry{}
)

// Lookup returns the executable path of the process that owns the local
// socket addr ("tcp" or "udp"). Results are cached for a few seconds, since
// one application opens many connections in a row.
func Lookup(network string, addr netip.AddrPort) (string, error) {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	k := cacheKey{network, addr}
	cacheMu.Lock()
	if e, ok := cache[k]; ok && time.Since(e.at) < 3*time.Second {
		cacheMu.Unlock()
		return e.path, e.err
	}
	cacheMu.Unlock()
	path, err := lookup(network, addr)
	cacheMu.Lock()
	if len(cache) > 4096 {
		cache = map[cacheKey]cacheEntry{}
	}
	cache[k] = cacheEntry{path, err, time.Now()}
	cacheMu.Unlock()
	return path, err
}

// Name returns the lower-case file name of an executable path.
func Name(path string) string {
	return strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
}

// Process is a running program, for the picker in the interface.
type Process struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// List returns running programs, one entry per executable name.
func List() ([]Process, error) {
	ps, err := list()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Process
	for _, p := range ps {
		n := strings.ToLower(p.Name)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

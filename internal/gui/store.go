// Package gui implements the desktop client: state, connection logic, a local
// HTTP API and the embedded web interface.
package gui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/links"
)

// Profile is a server the user can connect to.
type Profile struct {
	ID    string `json:"id"`
	SubID string `json:"subId,omitempty"` // set when it came from a subscription
	links.Link
}

// Subscription is a URL returning a list of links.
type Subscription struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

// Settings are user preferences.
type Settings struct {
	Mode        string              `json:"mode"`    // "proxy" or "tun"
	Routing     string              `json:"routing"` // preset: smart, blocked, global, custom
	CustomRules []config.RuleConfig `json:"customRules,omitempty"`
	SystemProxy bool                `json:"systemProxy"`
	SocksPort   int                 `json:"socksPort"`
	HTTPPort    int                 `json:"httpPort"`
	Autostart   bool                `json:"autostart"`
	AutoConnect bool                `json:"autoConnect"`
	GeoAuto     bool                `json:"geoAuto"`
	GeositeURL  string              `json:"geositeUrl"`
	GeoipURL    string              `json:"geoipUrl"`
	GeoUpdated  time.Time           `json:"geoUpdated"`
	Fingerprint string              `json:"fingerprint,omitempty"` // overrides profiles when set
	LogLevel    string              `json:"logLevel"`
}

func defaultSettings() Settings {
	return Settings{
		Mode: "proxy", Routing: "smart", SystemProxy: true,
		SocksPort: 10808, HTTPPort: 10809, GeoAuto: true, LogLevel: "info",
		GeositeURL: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
		GeoipURL:   "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
	}
}

// State is everything persisted to disk.
type State struct {
	Profiles      []Profile      `json:"profiles"`
	Subscriptions []Subscription `json:"subscriptions"`
	Selected      string         `json:"selected"`
	Settings      Settings       `json:"settings"`
}

// Store persists State as JSON in the data directory.
type Store struct {
	dir string
	mu  sync.Mutex
	st  State
}

// DataDir returns %APPDATA%\cypher (or the OS equivalent).
func DataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "cypher")
}

// OpenStore loads (or creates) the state in dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, st: State{Settings: defaultSettings()}}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(b, &s.st); err != nil {
			// Keep the broken file for the user and start fresh.
			os.Rename(filepath.Join(dir, "state.json"), filepath.Join(dir, "state.broken.json"))
			s.st = State{Settings: defaultSettings()}
		}
	}
	return s, nil
}

// Get returns a copy of the state.
func (s *Store) Get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.st)
	var c State
	json.Unmarshal(b, &c)
	return c
}

// Update changes the state under lock and saves it atomically.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.st); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "state.json"))
}

func newID() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

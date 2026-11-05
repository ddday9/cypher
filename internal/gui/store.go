// Package gui implements the desktop client: state, connection logic, a local
// HTTP API and the embedded web interface.
package gui

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/geo"
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
	Mode        string              `json:"mode"`                  // "proxy" or "tun"
	Routing     string              `json:"routing"`               // preset: smart, blocked, global, custom
	UserRules   []UserRule          `json:"userRules,omitempty"`   // checked before the preset
	CustomRules []config.RuleConfig `json:"customRules,omitempty"` // advanced, Xray JSON
	// DefaultAction applies with the "custom" preset to everything no rule matched.
	DefaultAction string    `json:"defaultAction,omitempty"`
	SystemProxy   bool      `json:"systemProxy"`
	SocksPort     int       `json:"socksPort"`
	HTTPPort      int       `json:"httpPort"`
	Autostart     bool      `json:"autostart"`
	AutoConnect   bool      `json:"autoConnect"`
	GeoAuto       bool      `json:"geoAuto"`
	GeoSource     string    `json:"geoSource"`        // preset ID or "custom"
	GeoInterval   int       `json:"geoIntervalHours"` // refresh period
	GeositeURL    string    `json:"geositeUrl"`
	GeoipURL      string    `json:"geoipUrl"`
	GeoUpdated    time.Time `json:"geoUpdated"`
	Fingerprint   string    `json:"fingerprint,omitempty"` // overrides profiles when set
	AntiFreeze    string    `json:"antiFreeze,omitempty"`  // auto (default), on, off; overrides profiles
	LogLevel      string    `json:"logLevel"`
}

func defaultSettings() Settings {
	return Settings{
		Mode: "proxy", Routing: "smart", SystemProxy: true,
		SocksPort: 10808, HTTPPort: 10809, GeoAuto: true, LogLevel: "info",
		GeoSource: geo.Presets[0].ID, GeoInterval: 24,
		GeositeURL: geo.Presets[0].Geosite, GeoipURL: geo.Presets[0].Geoip,
	}
}

// UserRule is one line of the rule editor.
type UserRule struct {
	Type   string `json:"type"`   // domain, full, keyword, geosite, ip, geoip, port, process
	Value  string `json:"value"`  // several values separated by commas or spaces
	Action string `json:"action"` // proxy, direct, block
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

// DataDir returns %APPDATA%\nevio (or the OS equivalent). Data of
// earlier versions in %APPDATA%\cypher is moved there on first start.
func DataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	dir := filepath.Join(base, "nevio")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		old := filepath.Join(base, "cypher")
		if _, err := os.Stat(filepath.Join(old, "state.json")); err == nil {
			os.Rename(old, dir)
		}
	}
	return dir
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
		// Fields added after the state was saved keep their defaults, since
		// unmarshalling only overwrites what the file contains. A file from a
		// version without geo sources has its own URLs: treat them as custom.
		if !bytes.Contains(b, []byte(`"geoSource"`)) {
			s.st.Settings.GeoSource = "custom"
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

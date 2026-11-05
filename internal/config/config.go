// Package config defines the JSON configuration for client and server.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Config is the root of a cypher configuration file. A file with a "server"
// section runs a server; otherwise it runs a client.
type Config struct {
	Log       LogConfig        `json:"log"`
	Server    *ServerConfig    `json:"server,omitempty"`
	Inbounds  []InboundConfig  `json:"inbounds,omitempty"`
	Outbounds []OutboundConfig `json:"outbounds,omitempty"`
	Routing   RoutingConfig    `json:"routing"`

	// Path is the config file itself; Dir is its directory (used to resolve
	// relative paths).
	Path string `json:"-"`
	Dir  string `json:"-"`
}

type LogConfig struct {
	Level string `json:"level"` // debug, info, warn, error
}

type ServerConfig struct {
	Listen   string `json:"listen"`             // e.g. ":443"
	CertFile string `json:"certFile,omitempty"` // fullchain.pem
	KeyFile  string `json:"keyFile,omitempty"`  // privkey.pem
	// ACME obtains and renews a certificate automatically (Let's Encrypt by
	// default) instead of certFile/keyFile. It uses the TLS-ALPN-01
	// challenge on the listen port, so port 80 is not needed — but the
	// server must be reachable on port 443 from the internet.
	ACME     *ACMEConfig    `json:"acme,omitempty"`
	Users    []UserConfig   `json:"users"`
	Fallback FallbackConfig `json:"fallback"`
	// AllowPrivate lets clients reach loopback/LAN addresses of the server.
	AllowPrivate bool `json:"allowPrivate"`
}

type ACMEConfig struct {
	Domain   string `json:"domain"`
	Email    string `json:"email,omitempty"`
	CacheDir string `json:"cacheDir,omitempty"` // where certificates are stored; default "acme" next to the config
	// DirectoryURL selects another ACME CA (e.g. Let's Encrypt staging);
	// CA is an extra root (PEM) to trust when talking to it.
	DirectoryURL string `json:"directoryURL,omitempty"`
	CA           string `json:"ca,omitempty"`
}

type UserConfig struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// FallbackConfig is the website shown to anyone who is not a valid client.
type FallbackConfig struct {
	Dir   string `json:"dir,omitempty"`   // serve static files from this directory
	Proxy string `json:"proxy,omitempty"` // or reverse-proxy to this URL, e.g. http://127.0.0.1:8080
}

type InboundConfig struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`             // socks, http, tun
	Listen string `json:"listen,omitempty"` // socks/http: 127.0.0.1:10808

	// tun: capture all traffic of the system.
	Name      string   `json:"name,omitempty"`      // interface name, default "cypher"
	MTU       int      `json:"mtu,omitempty"`       // default 1500
	Address   string   `json:"address,omitempty"`   // default "172.19.0.1/30"
	Address6  string   `json:"address6,omitempty"`  // default "fdfe:dcba:9876::1/126"; "off" disables IPv6
	AutoRoute *bool    `json:"autoRoute,omitempty"` // route traffic into the interface; default true
	Routes    []string `json:"routes,omitempty"`    // what to route; default everything
	// DNSHijack sends every DNS query (port 53, any address) to this server,
	// through the routing rules — by default through the tunnel, so queries
	// do not leak to the ISP. Default "1.1.1.1:53"; "off" disables.
	DNSHijack string `json:"dnsHijack,omitempty"`
	// Sniff reads the domain from TLS SNI / HTTP Host so that domain rules
	// (geosite) work for connections made by IP. Default true.
	Sniff *bool `json:"sniff,omitempty"`
}

type OutboundConfig struct {
	Tag  string `json:"tag"`
	Type string `json:"type"` // cypher, direct, block

	// cypher
	Server      string `json:"server,omitempty"`      // host:port
	ServerName  string `json:"serverName,omitempty"`  // TLS SNI; defaults to the server host
	Key         string `json:"key,omitempty"`         // user key from `cypher genkey`
	Fingerprint string `json:"fingerprint,omitempty"` // firefox (default), chrome, safari, edge, ios, random
	CA          string `json:"ca,omitempty"`          // extra CA certificate (PEM) to trust
	Insecure    bool   `json:"insecure,omitempty"`    // skip certificate verification (testing only)

	// Connections is how many TLS connections to keep in parallel (default 2).
	Connections int             `json:"connections,omitempty"`
	Rotation    *RotationConfig `json:"rotation,omitempty"`
}

// RotationConfig controls how long a tunnel connection lives. Each value is
// a range ("5m-20m"); every connection draws its own random limit. When a
// limit is hit the connection takes no new streams and closes once its
// existing streams finish.
type RotationConfig struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Age       string `json:"age,omitempty"`       // default "5m-20m"
	Megabytes string `json:"megabytes,omitempty"` // default "64-512"
	Idle      string `json:"idle,omitempty"`      // close when unused for; default "1m-3m"
}

type RoutingConfig struct {
	Geosite string `json:"geosite,omitempty"` // path to geosite.dat
	Geoip   string `json:"geoip,omitempty"`   // path to geoip.dat
	// DomainStrategy: "AsIs" (default) or "IPIfNonMatch" — resolve the domain
	// and retry IP rules when no rule matched by domain. Note that
	// IPIfNonMatch performs local DNS lookups.
	DomainStrategy string       `json:"domainStrategy,omitempty"`
	Rules          []RuleConfig `json:"rules,omitempty"`
	// Default outbound tag; defaults to the first outbound.
	Default string `json:"default,omitempty"`
}

// RuleConfig matches when every specified field matches.
type RuleConfig struct {
	Domain     []string `json:"domain,omitempty"`
	IP         []string `json:"ip,omitempty"`
	Port       PortList `json:"port,omitempty"`
	Network    string   `json:"network,omitempty"` // "tcp", "udp" or "tcp,udp"
	InboundTag []string `json:"inboundTag,omitempty"`
	Outbound   string   `json:"outbound"`
}

// PortList accepts either a number (443) or a string ("80,443,1000-2000").
type PortList string

func (p *PortList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*p = PortList(s)
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("port must be a number or a string: %w", err)
	}
	*p = PortList(strconv.Itoa(n))
	return nil
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	c.Dir = dirOf(path)
	return &c, nil
}

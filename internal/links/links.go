// Package links encodes server profiles as share links and parses
// subscriptions (lists of links).
//
//	cypher://KEY@host:port?sni=NAME&fp=FINGERPRINT&conn=N#Display%20name
package links

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ddday9/cypher/internal/protocol"
)

const Scheme = "cypher"

// Link is a server profile.
type Link struct {
	Name        string `json:"name"`
	Server      string `json:"server"` // host:port
	Key         string `json:"key"`
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Connections int    `json:"connections,omitempty"`
}

// Format returns the share link.
func Format(l Link) string {
	u := url.URL{Scheme: Scheme, User: url.User(l.Key), Host: l.Server, Fragment: l.Name}
	q := url.Values{}
	if l.ServerName != "" {
		q.Set("sni", l.ServerName)
	}
	if l.Fingerprint != "" {
		q.Set("fp", l.Fingerprint)
	}
	if l.Connections > 0 {
		q.Set("conn", strconv.Itoa(l.Connections))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Parse decodes a share link.
func Parse(s string) (Link, error) {
	var l Link
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return l, err
	}
	if u.Scheme != Scheme {
		return l, fmt.Errorf("not a %s:// link", Scheme)
	}
	if u.User == nil {
		return l, errors.New("link has no key")
	}
	l.Key = u.User.Username()
	if _, err := protocol.ParseKey(l.Key); err != nil {
		return l, err
	}
	l.Server = u.Host
	if _, port, err := net.SplitHostPort(l.Server); err != nil || port == "" {
		l.Server = net.JoinHostPort(strings.Trim(u.Host, "[]"), "443")
	}
	q := u.Query()
	l.ServerName = q.Get("sni")
	l.Fingerprint = q.Get("fp")
	if c := q.Get("conn"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 && n <= 16 {
			l.Connections = n
		}
	}
	l.Name = u.Fragment
	if l.Name == "" {
		host, _, _ := net.SplitHostPort(l.Server)
		l.Name = host
	}
	return l, nil
}

// ParseList extracts every link from text: one link per line, optionally
// base64-encoded as a whole (the usual subscription format).
func ParseList(text string) ([]Link, []error) {
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "://") {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(strings.Join(strings.Fields(text), "")); err == nil {
				text = string(b)
				break
			}
		}
	}
	var out []Link
	var errs []error
	for line := range strings.FieldsSeq(text) {
		if !strings.HasPrefix(line, Scheme+"://") {
			continue
		}
		l, err := Parse(line)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, l)
	}
	return out, errs
}

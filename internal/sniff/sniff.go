// Package sniff extracts the destination domain from the first bytes of a
// connection: the SNI of a TLS ClientHello or the Host header of HTTP/1.x.
package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// ErrNeedMore means the data is a valid prefix but incomplete.
var ErrNeedMore = errors.New("need more data")

// ErrUnknown means the data is not a protocol we can sniff.
var ErrUnknown = errors.New("unknown protocol")

// Domain returns the domain found in b, ErrNeedMore or ErrUnknown.
func Domain(b []byte) (string, error) {
	if len(b) == 0 {
		return "", ErrNeedMore
	}
	if b[0] == 0x16 {
		return tlsSNI(b)
	}
	if b[0] >= 'A' && b[0] <= 'Z' {
		return httpHost(b)
	}
	return "", ErrUnknown
}

// tlsSNI parses a TLS record containing a ClientHello.
func tlsSNI(b []byte) (string, error) {
	if len(b) < 5 {
		return "", ErrNeedMore
	}
	if b[1] != 3 {
		return "", ErrUnknown
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen > 1<<14+2048 {
		return "", ErrUnknown
	}
	if len(b) < 5+4 {
		return "", ErrNeedMore
	}
	if b[5] != 1 { // ClientHello
		return "", ErrUnknown
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	// The ClientHello may span several records; we only parse the first one,
	// which nearly always holds all the extensions we need.
	body := b[9:]
	need := min(hsLen, recLen-4)
	if len(body) < need {
		return "", ErrNeedMore
	}
	body = body[:need]

	p := parser{b: body}
	p.skip(2 + 32)       // version, random
	p.skip(int(p.u8()))  // session id
	p.skip(int(p.u16())) // cipher suites
	p.skip(int(p.u8()))  // compression methods
	extLen := int(p.u16())
	if p.err != nil {
		return "", ErrUnknown
	}
	ext := parser{b: p.rest(extLen)}
	for ext.err == nil && len(ext.b) >= 4 {
		typ, l := ext.u16(), int(ext.u16())
		data := ext.rest(l)
		if ext.err != nil {
			break
		}
		if typ != 0 { // server_name
			continue
		}
		sn := parser{b: data}
		sn.u16() // list length
		for sn.err == nil && len(sn.b) >= 3 {
			nameType, nl := sn.u8(), int(sn.u16())
			name := sn.rest(nl)
			if sn.err == nil && nameType == 0 && validHost(string(name)) {
				return strings.ToLower(string(name)), nil
			}
		}
	}
	return "", ErrUnknown
}

var methods = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"}

// methodOK reports whether b starts with (a prefix of) "METHOD ".
func methodOK(b []byte) bool {
	tok, _, complete := bytes.Cut(b, []byte(" "))
	for _, m := range methods {
		if complete && string(tok) == m || !complete && strings.HasPrefix(m, string(tok)) {
			return true
		}
	}
	return false
}

func httpHost(b []byte) (string, error) {
	if !methodOK(b[:min(len(b), 8)]) {
		return "", ErrUnknown
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end]
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 || !bytes.Contains(lines[0], []byte(" HTTP/1.")) {
		if end < 0 && len(b) < 4096 && !bytes.Contains(b, []byte("\r\n")) {
			return "", ErrNeedMore
		}
		return "", ErrUnknown
	}
	for _, l := range lines[1:] {
		k, v, ok := bytes.Cut(l, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			h := string(bytes.TrimSpace(v))
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			h = strings.Trim(h, "[]")
			if validHost(h) {
				return strings.ToLower(h), nil
			}
			return "", ErrUnknown
		}
	}
	if end < 0 && len(b) < 8192 {
		return "", ErrNeedMore
	}
	return "", ErrUnknown
}

// validHost accepts domain names, not IP literals (those add nothing).
func validHost(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, c := range h {
		if !(c == '.' || c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return strings.Contains(h, ".")
}

type parser struct {
	b   []byte
	err error
}

func (p *parser) rest(n int) []byte {
	if p.err != nil || n > len(p.b) || n < 0 {
		p.err = ErrUnknown
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}
func (p *parser) skip(n int) { p.rest(n) }
func (p *parser) u8() byte {
	v := p.rest(1)
	if v == nil {
		return 0
	}
	return v[0]
}
func (p *parser) u16() uint16 {
	v := p.rest(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

// Peek reads from conn until a domain is found, the protocol is unknown, or
// timeout passes (server-speaks-first protocols send nothing). It returns
// the domain (possibly empty) and the bytes consumed, which the caller must
// replay.
func Peek(conn net.Conn, timeout time.Duration) (string, []byte) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	for len(buf) < 32*1024 {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			d, serr := Domain(buf)
			if serr != ErrNeedMore {
				return d, buf
			}
		}
		if err != nil {
			return "", buf
		}
	}
	return "", buf
}

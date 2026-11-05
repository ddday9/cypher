// Package protocol implements the cypher wire protocol (see docs/protocol.md).
package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	KeySize        = 32
	nonceSize      = 16
	timestampSize  = 8
	padLenSize     = 2
	macSize        = 32
	AuthHeaderSize = nonceSize + timestampSize + padLenSize + macSize // 58

	// MaxClockSkew is how far the client timestamp may drift from server time.
	MaxClockSkew = 120 * time.Second

	// maxAuthPadding bounds the random padding sent after the auth header.
	maxAuthPadding = 768
)

var authLabel = []byte("cypher/v1/auth")

// ErrNotAuthenticated means the peer did not present a valid auth header.
// The bytes read so far must be handed to the fallback website.
var ErrNotAuthenticated = errors.New("not authenticated")

// Key is a per-user pre-shared secret.
type Key [KeySize]byte

// GenerateKey returns a new random key.
func GenerateKey() Key {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return k
}

// ParseKey decodes a base64 (URL-safe or standard, padded or not) key.
func ParseKey(s string) (Key, error) {
	var k Key
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil {
			if len(b) != KeySize {
				return k, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(b))
			}
			copy(k[:], b)
			return k, nil
		}
	}
	return k, errors.New("key is not valid base64")
}

func (k Key) String() string { return base64.RawURLEncoding.EncodeToString(k[:]) }

func computeMAC(key Key, hdr []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(authLabel)
	m.Write(hdr[:nonceSize+timestampSize+padLenSize])
	return m.Sum(nil)
}

// isHTTPStart reports whether b could be the first byte of an HTTP/1.x
// request line or the HTTP/2 preface ("PRI * HTTP/2.0"). Every method token
// starts with an upper-case ASCII letter.
func isHTTPStart(b byte) bool { return b >= 'A' && b <= 'Z' }

// BuildAuth returns the auth header followed by random padding. The client
// sends it as the first bytes inside the TLS tunnel.
func BuildAuth(key Key, now time.Time) []byte { return BuildAuthExt(key, now, nil) }

// BuildAuthExt is BuildAuth with a protocol extension carried inside the
// padding. Servers of version 1 discard the padding, so the extension is
// invisible to them and the connection works as version 1.
func BuildAuthExt(key Key, now time.Time, ext *Ext) []byte {
	var pl [2]byte
	rand.Read(pl[:])
	padLen := int(binary.BigEndian.Uint16(pl[:])) % (maxAuthPadding + 1)
	if ext != nil {
		// Room for the extension; the length stays uniformly random.
		padLen = extSize + int(binary.BigEndian.Uint16(pl[:]))%(maxAuthPadding-extSize+1)
	}

	buf := make([]byte, AuthHeaderSize+padLen)
	for {
		rand.Read(buf[:nonceSize])
		// Never look like HTTP, so the server can route real browsers to the
		// fallback website after the very first byte.
		if !isHTTPStart(buf[0]) {
			break
		}
	}
	binary.BigEndian.PutUint64(buf[nonceSize:], uint64(now.Unix()))
	binary.BigEndian.PutUint16(buf[nonceSize+timestampSize:], uint16(padLen))
	copy(buf[nonceSize+timestampSize+padLenSize:], computeMAC(key, buf))
	rand.Read(buf[AuthHeaderSize:])
	if ext != nil {
		ext.encode(buf[AuthHeaderSize:], key, buf[:nonceSize])
	}
	return buf
}

// User is a server-side account.
type User struct {
	Name string
	Key  Key
}

// Authenticator verifies client auth headers and rejects replays.
type Authenticator struct {
	usersMu sync.RWMutex
	users   []User
	now     func() time.Time

	mu        sync.Mutex
	seen      map[[nonceSize]byte]int64
	lastSweep int64
}

// NewAuthenticator creates an Authenticator for the given users.
func NewAuthenticator(users []User) *Authenticator {
	return &Authenticator{users: users, now: time.Now, seen: make(map[[nonceSize]byte]int64)}
}

// verify checks a complete header and returns the user and padding length.
// HasKey reports whether a user with key k is currently allowed.
func (a *Authenticator) HasKey(k Key) bool {
	a.usersMu.RLock()
	defer a.usersMu.RUnlock()
	for _, u := range a.users {
		if u.Key == k {
			return true
		}
	}
	return false
}

// SetUsers replaces the user list; new connections use it immediately.
func (a *Authenticator) SetUsers(users []User) {
	a.usersMu.Lock()
	a.users = users
	a.usersMu.Unlock()
}

func (a *Authenticator) verify(hdr []byte) (*User, int, bool) {
	var user *User
	a.usersMu.RLock()
	for i := range a.users {
		mac := computeMAC(a.users[i].Key, hdr)
		if hmac.Equal(mac, hdr[nonceSize+timestampSize+padLenSize:AuthHeaderSize]) {
			u := a.users[i]
			user = &u
			break
		}
	}
	a.usersMu.RUnlock()
	if user == nil {
		return nil, 0, false
	}
	now := a.now().Unix()
	ts := int64(binary.BigEndian.Uint64(hdr[nonceSize:]))
	skew := int64(MaxClockSkew / time.Second)
	if ts < now-skew || ts > now+skew {
		return nil, 0, false
	}
	var nonce [nonceSize]byte
	copy(nonce[:], hdr)

	a.mu.Lock()
	defer a.mu.Unlock()
	if now-a.lastSweep > skew {
		for n, t := range a.seen {
			if t < now-2*skew {
				delete(a.seen, n)
			}
		}
		a.lastSweep = now
	}
	if _, dup := a.seen[nonce]; dup {
		return nil, 0, false
	}
	a.seen[nonce] = now
	padLen := int(binary.BigEndian.Uint16(hdr[nonceSize+timestampSize:]))
	return user, padLen, true
}

// ReadAuth reads and verifies the client auth header from conn.
//
// On success it returns the user. If the peer is not a valid client it
// returns ErrNotAuthenticated together with every byte read so far, so the
// caller can replay them into the fallback website. Any other error is an
// I/O error and the connection should simply be closed.
func (a *Authenticator) ReadAuth(conn net.Conn) (*User, []byte, error) {
	res, prefix, err := a.ReadAuthExt(conn)
	if res == nil {
		return nil, prefix, err
	}
	return res.User, prefix, err
}

// AuthResult is a verified client: its user and, for clients of version 2
// or later, the extension it sent.
type AuthResult struct {
	User *User
	Ext  *Ext // nil for version 1 clients
}

// ReadAuthExt is ReadAuth that also returns the client's extension.
func (a *Authenticator) ReadAuthExt(conn io.Reader) (*AuthResult, []byte, error) {
	buf := make([]byte, AuthHeaderSize)
	n := 0
	for n < AuthHeaderSize {
		m, err := conn.Read(buf[n:])
		n += m
		if n > 0 && isHTTPStart(buf[0]) {
			return nil, buf[:n], ErrNotAuthenticated
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, buf[:n], ErrNotAuthenticated
			}
			return nil, buf[:n], err
		}
	}
	user, padLen, ok := a.verify(buf)
	if !ok {
		return nil, buf, ErrNotAuthenticated
	}
	if padLen > maxAuthPadding {
		return nil, buf, ErrNotAuthenticated
	}
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(conn, pad); err != nil {
		return nil, nil, err
	}
	return &AuthResult{User: user, Ext: parseExt(pad, user.Key, buf[:nonceSize])}, nil, nil
}

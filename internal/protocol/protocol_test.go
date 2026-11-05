package protocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/netx"
)

func TestKeyRoundTrip(t *testing.T) {
	k := GenerateKey()
	got, err := ParseKey(k.String())
	if err != nil || got != k {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func readAuth(t *testing.T, a *Authenticator, data []byte) (*User, []byte, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		c2.Write(data)
		c2.Close()
	}()
	return a.ReadAuth(c1)
}

func TestAuth(t *testing.T) {
	alice, bob := GenerateKey(), GenerateKey()
	a := NewAuthenticator([]User{{Name: "alice", Key: alice}, {Name: "bob", Key: bob}})

	hdr := BuildAuth(bob, time.Now())
	u, _, err := readAuth(t, a, hdr)
	if err != nil || u.Name != "bob" {
		t.Fatalf("valid auth rejected: user=%v err=%v", u, err)
	}

	// Replay of the same header must be rejected.
	if _, _, err := readAuth(t, a, hdr); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("replay accepted: %v", err)
	}

	// Unknown key.
	if _, prefix, err := readAuth(t, a, BuildAuth(GenerateKey(), time.Now())); !errors.Is(err, ErrNotAuthenticated) || len(prefix) != AuthHeaderSize {
		t.Fatalf("unknown key: err=%v prefix=%d", err, len(prefix))
	}

	// Stale timestamp.
	if _, _, err := readAuth(t, a, BuildAuth(alice, time.Now().Add(-10*time.Minute))); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("stale timestamp accepted: %v", err)
	}

	// An HTTP request is detected from its first byte and returned intact.
	req := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, prefix, err := readAuth(t, a, req)
	if !errors.Is(err, ErrNotAuthenticated) || !bytes.HasPrefix(req, prefix) || len(prefix) == 0 {
		t.Fatalf("http request: err=%v prefix=%q", err, prefix)
	}
}

func TestAuthNeverLooksLikeHTTP(t *testing.T) {
	k := GenerateKey()
	for range 2000 {
		if isHTTPStart(BuildAuth(k, time.Now())[0]) {
			t.Fatal("auth header starts with an HTTP-like byte")
		}
	}
}

func TestRecordConn(t *testing.T) {
	c1, c2 := net.Pipe()
	prefix := []byte("PREFIX")
	w := NewRecordConn(c1, prefix)

	payload := make([]byte, 100_000)
	rand.Read(payload)
	go func() {
		w.Write(payload[:10])
		w.Write(payload[10:])
		w.Write(nil)
		c1.Close()
	}()

	got := make([]byte, len(prefix))
	if _, err := io.ReadFull(c2, got); err != nil || !bytes.Equal(got, prefix) {
		t.Fatalf("prefix: %q %v", got, err)
	}
	r := NewRecordConn(c2, nil)
	all, err := io.ReadAll(r)
	if err != nil && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if !bytes.Equal(all, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(all))
	}
}

func TestRequestRoundTrip(t *testing.T) {
	for _, host := range []string{"example.com", "1.2.3.4", "2001:db8::1"} {
		var buf bytes.Buffer
		want := Request{Cmd: CmdTCP, Dest: netx.Destination{Network: "tcp", Host: host, Port: 443}}
		if err := WriteRequest(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadRequest(&buf)
		if err != nil || got != want {
			t.Fatalf("%s: got %+v, err %v", host, got, err)
		}
	}
}

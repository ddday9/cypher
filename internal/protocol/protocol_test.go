package protocol

import (
	"bytes"
	"fmt"
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

// frame builds a smux v2 frame.
func frame(cmd byte, sid uint32, data []byte) []byte {
	f := []byte{smuxVersion, cmd, byte(len(data)), byte(len(data) >> 8),
		byte(sid), byte(sid >> 8), byte(sid >> 16), byte(sid >> 24)}
	return append(f, data...)
}

// wireRecords writes frames through a RecordConn and returns the sizes of
// the records seen on the wire (data, padding).
func wireRecords(t *testing.T, frames [][]byte) [][2]int {
	t.Helper()
	a, b := net.Pipe()
	w := NewRecordConn(a, nil)
	w.written = earlyRecords // skip session-start shaping
	go func() {
		for _, f := range frames {
			w.Write(f)
		}
		a.Close()
	}()
	var recs [][2]int
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(b, hdr[:]); err != nil {
			return recs
		}
		d, p := int(hdr[0])<<8|int(hdr[1]), int(hdr[2])<<8|int(hdr[3])
		io.CopyN(io.Discard, b, int64(d+p))
		recs = append(recs, [2]int{d, p})
	}
}

func TestStreamStartIsShaped(t *testing.T) {
	big := make([]byte, 12000)
	var frames [][]byte
	for range earlyStreamFrame {
		frames = append(frames, frame(smuxCmdPSH, 7, big))
	}
	frames = append(frames, frame(smuxCmdPSH, 7, big)) // past the early phase
	recs := wireRecords(t, frames)

	last := recs[len(recs)-1]
	if last[0] != len(big)+smuxHeaderLen || last[1] != 0 {
		t.Fatalf("late frame should be one unpadded record, got %v", last)
	}
	for _, r := range recs[:len(recs)-1] {
		if r[0] > shapedChunkMax {
			t.Fatalf("early frame chunk too large: %v", r)
		}
	}
	if len(recs) < 2*earlyStreamFrame {
		t.Fatalf("early frames were not split: %d records", len(recs))
	}

	// A new stream (new sid) is shaped again, even mid-session.
	recs = wireRecords(t, [][]byte{frame(smuxCmdPSH, 9, big)})
	if len(recs) < 2 {
		t.Fatalf("new stream not shaped: %v", recs)
	}
}

func TestAuthExtension(t *testing.T) {
	k := GenerateKey()
	a := NewAuthenticator([]User{{Name: "u", Key: k}})
	ext := &Ext{Flags: FlagV2 | FlagSegmented, Seq: 7}
	rand.Read(ext.Session[:])
	for range 50 {
		hdr := BuildAuthExt(k, time.Now(), ext)
		if len(hdr) < AuthHeaderSize+extSize || len(hdr) > AuthHeaderSize+maxAuthPadding {
			t.Fatalf("length %d", len(hdr))
		}
		c1, c2 := net.Pipe()
		go func() { c2.Write(hdr); c2.Close() }()
		res, _, err := a.ReadAuthExt(c1)
		if err != nil || res.Ext == nil || *res.Ext != *ext {
			t.Fatalf("ext round trip: %+v %v", res, err)
		}
	}
	// A v1 client (no extension) and a forged extension both read as nil.
	c1, c2 := net.Pipe()
	go func() { c2.Write(BuildAuth(k, time.Now())); c2.Close() }()
	if res, _, err := a.ReadAuthExt(c1); err != nil || res.Ext != nil {
		t.Fatalf("v1 client: %+v %v", res, err)
	}
	hdr := BuildAuthExt(k, time.Now(), ext)
	hdr[AuthHeaderSize+5] ^= 1 // flip a flag bit
	c3, c4 := net.Pipe()
	go func() { c4.Write(hdr); c4.Close() }()
	if res, _, err := a.ReadAuthExt(c3); err != nil || res.Ext != nil {
		t.Fatalf("forged ext accepted: %+v %v", res, err)
	}
}

func TestControlRecords(t *testing.T) {
	a, b := net.Pipe()
	w, r := NewRecordConn(a, nil), NewRecordConn(b, nil)
	got := make(chan string, 4)
	r.SetControlHandler(func(typ byte, body []byte) { got <- fmt.Sprintf("%d:%s", typ, body) })
	go func() {
		w.WriteControl(CtlHello, []byte("hi"))
		w.Write([]byte("data"))
		w.WriteControl(CtlPing, []byte("p"))
		w.Write([]byte("more"))
		a.Close()
	}()
	all, _ := io.ReadAll(r)
	if string(all) != "datamore" {
		t.Fatalf("data mixed with control records: %q", all)
	}
	if g1, g2 := <-got, <-got; g1 != "1:hi" || g2 != "2:p" {
		t.Fatalf("control: %s %s", g1, g2)
	}
}

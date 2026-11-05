package sniff

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// clientHello captures a real ClientHello produced by uTLS (Chrome).
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		uc := utls.UClient(a, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		uc.Handshake()
	}()
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) >= 5 && len(buf) >= 5+int(buf[3])<<8+int(buf[4]) || err != nil {
			break
		}
	}
	a.Close()
	b.Close()
	return buf
}

func TestTLS(t *testing.T) {
	for _, sni := range []string{"www.example.com", "Mixed.Case.Org"} {
		ch := clientHello(t, sni)
		got, err := Domain(ch)
		if err != nil || got != toLower(sni) {
			t.Fatalf("%s: got %q %v (hello %d bytes)", sni, got, err, len(ch))
		}
		// Every strict prefix must ask for more data, never fail.
		for _, n := range []int{1, 4, 10, 100, len(ch) - 1} {
			if _, err := Domain(ch[:n]); err != ErrNeedMore {
				t.Fatalf("prefix %d: %v", n, err)
			}
		}
	}
	// Go's own client too.
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: "go.example", InsecureSkipVerify: true}).Handshake()
	d, _ := Peek(b, time.Second)
	if d != "go.example" {
		t.Fatalf("go client: %q", d)
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestHTTP(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n":                   "example.com",
		"POST /x HTTP/1.1\r\nUser-Agent: a\r\nhost: A.B.c:8080\r\n\r\n": "a.b.c",
	}
	for in, want := range cases {
		if got, err := Domain([]byte(in)); err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	if _, err := Domain([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n")); err != ErrUnknown {
		t.Errorf("IP host: %v", err)
	}
	if _, err := Domain([]byte("GET / HTT")); err != ErrNeedMore {
		t.Errorf("partial: %v", err)
	}
	if _, err := Domain([]byte("SSH-2.0-OpenSSH")); err != ErrUnknown {
		t.Errorf("ssh: %v", err)
	}
	if _, err := Domain([]byte{0x00, 0x01}); err != ErrUnknown {
		t.Errorf("binary: %v", err)
	}
}

func TestPeekTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	start := time.Now()
	d, buf := Peek(b, 100*time.Millisecond) // server-first protocol: client sends nothing
	if d != "" || len(buf) != 0 || time.Since(start) > time.Second {
		t.Fatalf("got %q %d after %v", d, len(buf), time.Since(start))
	}
}

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
	"github.com/ddday9/cypher/internal/server"
	"golang.org/x/net/http2"
)

// writeCert creates a self-signed certificate for localhost.
func writeCert(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return
}

// echoServer echoes every connection back, line by line.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

type env struct {
	serverAddr string
	key        protocol.Key
	caFile     string
	keyFile    string
	pool       *x509.CertPool
}

func startServer(t *testing.T, allowPrivate bool) env {
	return startServerOpts(t, allowPrivate, nil)
}

func startServerWith(t *testing.T, setup func(*server.Server)) env {
	return startServerOpts(t, true, setup)
}

func startServerOpts(t *testing.T, allowPrivate bool, setup func(*server.Server)) env {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, pool := writeCert(t, dir)
	key := protocol.GenerateKey()
	s, err := server.New(&config.ServerConfig{
		CertFile:     certFile,
		KeyFile:      keyFile,
		Users:        []config.UserConfig{{Name: "test", Key: key.String()}},
		AllowPrivate: allowPrivate,
	}, func(p string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, ln)
	return env{serverAddr: ln.Addr().String(), key: key, caFile: certFile, keyFile: keyFile, pool: pool}
}

func (e env) outbound(t *testing.T, key protocol.Key) client.Outbound {
	t.Helper()
	_, port, _ := net.SplitHostPort(e.serverAddr)
	o, err := client.New(config.OutboundConfig{
		Tag: "proxy", Type: "cypher",
		Server: "localhost:" + port, Key: key.String(), CA: e.caFile,
	}, func(p string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func echoRoundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != msg+"\n" {
		t.Fatalf("echo: got %q, err %v", line, err)
	}
}

func TestTunnel(t *testing.T) {
	e := startServer(t, true)
	o := e.outbound(t, e.key)
	echo := echoServer(t)
	dest, _ := netx.ParseDestination("tcp", echo)

	// Many concurrent streams share one multiplexed session.
	errs := make(chan error, 20)
	for i := range 20 {
		go func() {
			c, err := o.Dial(context.Background(), dest)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			payload := bytes.Repeat([]byte{byte(i)}, 200_000)
			go c.Write(payload)
			got := make([]byte, len(payload))
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(c, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("stream %d: payload mismatch", i)
				return
			}
			errs <- nil
		}()
	}
	for range 20 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPrivateDestinationsBlockedByDefault(t *testing.T) {
	e := startServer(t, false)
	o := e.outbound(t, e.key)
	dest, _ := netx.ParseDestination("tcp", echoServer(t))
	_, err := o.Dial(context.Background(), dest)
	var se protocol.StatusError
	if !errors.As(err, &se) || byte(se) != protocol.StatusNotAllowed {
		t.Fatalf("expected not-allowed, got %v", err)
	}
	// A domain resolving to loopback must be blocked too.
	dest = netx.Destination{Network: "tcp", Host: "localhost", Port: dest.Port}
	if _, err := o.Dial(context.Background(), dest); !errors.As(err, &se) {
		t.Fatalf("expected not-allowed for localhost, got %v", err)
	}
}

func TestWrongKeyGetsWebsite(t *testing.T) {
	e := startServer(t, true)
	o := e.outbound(t, protocol.GenerateKey())
	dest, _ := netx.ParseDestination("tcp", echoServer(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := o.Dial(ctx, dest); err == nil {
		c.Close()
		t.Fatal("dial with a wrong key succeeded")
	}
}

// TestProbesSeeWebsite checks that a browser (HTTP/1.1 and HTTP/2) sees a
// normal website on the server port.
func TestProbesSeeWebsite(t *testing.T) {
	e := startServer(t, true)
	_, port, _ := net.SplitHostPort(e.serverAddr)
	url := "https://localhost:" + port + "/"

	for _, proto := range []string{"http/1.1", "h2"} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.pool, NextProtos: []string{proto}}}
		if proto == "h2" {
			if err := http2.ConfigureTransport(tr); err != nil {
				t.Fatal(err)
			}
		}
		hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		resp, err := hc.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "Welcome") {
			t.Fatalf("%s: status %d body %q", proto, resp.StatusCode, body)
		}
		wantMajor := 1
		if proto == "h2" {
			wantMajor = 2
		}
		if resp.ProtoMajor != wantMajor {
			t.Fatalf("%s: served over %s", proto, resp.Proto)
		}
		resp, err = hc.Get(url + "missing")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s: expected 404, got %d", proto, resp.StatusCode)
		}
		tr.CloseIdleConnections()
	}
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestClientInbounds runs the whole client: SOCKS5 and HTTP CONNECT inbounds,
// routing to the tunnel and to a block outbound.
func TestClientInbounds(t *testing.T) {
	e := startServer(t, true)
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(e.serverAddr)
	socksAddr, httpAddr := freePort(t), freePort(t)

	cfg := &config.Config{
		Inbounds: []config.InboundConfig{
			{Tag: "socks", Type: "socks", Listen: socksAddr},
			{Tag: "http", Type: "http", Listen: httpAddr},
		},
		Outbounds: []config.OutboundConfig{
			{Tag: "proxy", Type: "cypher", Server: "localhost:" + port, Key: e.key.String(), CA: e.caFile},
			{Tag: "block", Type: "block"},
		},
		Routing: config.RoutingConfig{Rules: []config.RuleConfig{
			{Domain: []string{"domain:blocked.test"}, Outbound: "block"},
		}},
		Dir: t.TempDir(),
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	time.Sleep(200 * time.Millisecond)

	echoPort := echo[strings.LastIndexByte(echo, ':')+1:]
	n := 0
	fmt.Sscanf(echoPort, "%d", &n)
	p := [2]byte{byte(n >> 8), byte(n)}

	// SOCKS5 CONNECT to 127.0.0.1:echoPort.
	sc, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	sc.SetDeadline(time.Now().Add(5 * time.Second))
	sc.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	io.ReadFull(sc, reply)
	sc.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(sc, rep); err != nil || rep[1] != 0 {
		t.Fatalf("socks reply %v err %v", rep, err)
	}
	echoRoundTrip(t, sc, "hello over socks")

	// SOCKS5 to a blocked domain gets "not allowed".
	bc, _ := net.Dial("tcp", socksAddr)
	defer bc.Close()
	bc.SetDeadline(time.Now().Add(5 * time.Second))
	bc.Write([]byte{5, 1, 0})
	io.ReadFull(bc, reply)
	d := "x.blocked.test"
	bc.Write(append(append([]byte{5, 1, 0, 3, byte(len(d))}, d...), 0, 80))
	if _, err := io.ReadFull(bc, rep); err != nil || rep[1] != 2 {
		t.Fatalf("blocked socks reply %v err %v", rep, err)
	}

	// HTTP CONNECT.
	hc, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	hc.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(hc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	br := bufio.NewReader(hc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	io.WriteString(hc, "hello over http\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "hello over http\n" {
		t.Fatalf("http echo: %q %v", line, err)
	}
}

// TestFingerprints checks that every supported ClientHello completes a
// handshake with the server.
func TestFingerprints(t *testing.T) {
	e := startServer(t, true)
	_, port, _ := net.SplitHostPort(e.serverAddr)
	dest, _ := netx.ParseDestination("tcp", echoServer(t))
	for _, fp := range []string{"", "firefox", "chrome", "safari", "edge", "ios", "random"} {
		o, err := client.New(config.OutboundConfig{
			Tag: "proxy", Type: "cypher", Server: "localhost:" + port,
			Key: e.key.String(), CA: e.caFile, Fingerprint: fp,
		}, func(p string) string { return p })
		if err != nil {
			t.Fatal(err)
		}
		c, err := o.Dial(context.Background(), dest)
		if err != nil {
			t.Errorf("fingerprint %q: %v", fp, err)
			o.Close()
			continue
		}
		echoRoundTrip(t, c, "hi "+fp)
		c.Close()
		o.Close()
	}
}

func TestFallbackSite(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, pool := writeCert(t, dir)
	site := filepath.Join(dir, "site")
	os.MkdirAll(filepath.Join(site, "sub"), 0o755)
	s, err := server.New(&config.ServerConfig{
		CertFile: certFile, KeyFile: keyFile,
		Users:    []config.UserConfig{{Key: protocol.GenerateKey().String()}},
		Fallback: config.FallbackConfig{Dir: site},
	}, func(p string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	get := func(path string) (int, string) {
		resp, err := hc.Get("https://localhost:" + port + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// Empty folder: the built-in page, not a directory listing.
	if code, body := get("/"); code != 200 || !strings.Contains(body, "Welcome") {
		t.Fatalf("empty site: %d %q", code, body)
	}
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>My site</h1>"), 0o644)
	if code, body := get("/"); code != 200 || !strings.Contains(body, "My site") {
		t.Fatalf("site: %d %q", code, body)
	}
	if code, _ := get("/sub/"); code != 404 {
		t.Fatalf("directory listing exposed: %d", code)
	}
}

// TestRevokeUser checks that SetUsers disconnects a revoked user at once and
// lets a newly added one in.
func TestRevokeUser(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeCert(t, dir)
	alice, bob := protocol.GenerateKey(), protocol.GenerateKey()
	s, err := server.New(&config.ServerConfig{
		CertFile: certFile, KeyFile: keyFile, AllowPrivate: true,
		Users: []config.UserConfig{{Name: "alice", Key: alice.String()}},
	}, func(p string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, ln)
	e := env{serverAddr: ln.Addr().String(), caFile: certFile}
	dest, _ := netx.ParseDestination("tcp", echoServer(t))

	oa := e.outbound(t, alice)
	c, err := oa.Dial(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, c, "before")

	// Bob is not a user yet.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if _, err := e.outbound(t, bob).Dial(ctx2, dest); err == nil {
		t.Fatal("unknown user connected")
	}
	// Replace alice by bob.
	if err := s.SetUsers([]config.UserConfig{{Name: "bob", Key: bob.String()}}); err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked user's stream still open")
	}
	cb, err := e.outbound(t, bob).Dial(context.Background(), dest)
	if err != nil {
		t.Fatalf("added user rejected: %v", err)
	}
	echoRoundTrip(t, cb, "bob")
	if err := s.SetUsers(nil); err == nil {
		t.Fatal("empty user list accepted")
	}
}

func TestServerRouting(t *testing.T) {
	e := startServerWith(t, func(s *server.Server) {
		if err := s.SetRouting(config.RoutingConfig{Rules: []config.RuleConfig{
			{Domain: []string{"domain:blocked.test"}, Outbound: "block"},
			{InboundTag: []string{"test"}, Port: "9", Outbound: "block"},
		}}, func(p string) string { return p }); err != nil {
			t.Fatal(err)
		}
	})
	o := e.outbound(t, e.key)
	var se protocol.StatusError
	_, err := o.Dial(context.Background(), netx.Destination{Network: "tcp", Host: "x.blocked.test", Port: 80})
	if !errors.As(err, &se) || byte(se) != protocol.StatusNotAllowed {
		t.Fatalf("domain rule: %v", err)
	}
	_, err = o.Dial(context.Background(), netx.Destination{Network: "tcp", Host: "127.0.0.1", Port: 9})
	if !errors.As(err, &se) || byte(se) != protocol.StatusNotAllowed {
		t.Fatalf("per-user rule: %v", err)
	}
	dest, _ := netx.ParseDestination("tcp", echoServer(t))
	c, err := o.Dial(context.Background(), dest)
	if err != nil {
		t.Fatalf("allowed destination: %v", err)
	}
	echoRoundTrip(t, c, "ok")
	// Only direct/block are valid on a server.
	id := func(p string) string { return p }
	s, err := server.New(&config.ServerConfig{CertFile: e.caFile, KeyFile: e.keyFile,
		Users: []config.UserConfig{{Key: protocol.GenerateKey().String()}}}, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouting(config.RoutingConfig{Rules: []config.RuleConfig{{Port: "1", Outbound: "proxy"}}}, id); err == nil {
		t.Fatal("proxy outbound accepted on the server")
	}
}

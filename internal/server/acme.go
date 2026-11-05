package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// certManager obtains and renews the certificate through ACME (Let's
// Encrypt). Renewal happens in the background 30 days before expiry and the
// new certificate is used for the next handshake — no restart needed.
type certManager struct {
	domain string
	m      *autocert.Manager
}

func newACME(cfg *config.ACMEConfig, resolve func(string) string) (*certManager, error) {
	domain := strings.ToLower(strings.TrimSpace(cfg.Domain))
	if domain == "" {
		return nil, errors.New("server.acme.domain is required")
	}
	cache := cfg.CacheDir
	if cache == "" {
		cache = "acme"
	}
	cache = resolve(cache)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, fmt.Errorf("acme cache: %w", err)
	}
	m := &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  autocert.HostWhitelist(domain),
		Cache:       autocert.DirCache(cache),
		Email:       cfg.Email,
		RenewBefore: 30 * 24 * time.Hour,
	}
	if cfg.DirectoryURL != "" {
		hc := http.DefaultClient
		if cfg.CA != "" {
			pem, err := os.ReadFile(resolve(cfg.CA))
			if err != nil {
				return nil, fmt.Errorf("acme ca: %w", err)
			}
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
			hc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		}
		m.Client = &acme.Client{DirectoryURL: cfg.DirectoryURL, HTTPClient: hc}
	}
	cm := &certManager{domain: domain, m: m}
	if cfg.HTTPListen != "" {
		// HTTP-01: the CA fetches http://domain/.well-known/acme-challenge/…
		// on port 80 (directly, or through nginx in front of this port).
		h := m.HTTPHandler(http.HandlerFunc(redirectToHTTPS))
		srv := &http.Server{Addr: cfg.HTTPListen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			slog.Info("ACME HTTP-01 listener", "addr", cfg.HTTPListen)
			if err := srv.ListenAndServe(); err != nil {
				slog.Error("ACME HTTP-01 listener stopped", "err", err)
			}
		}()
	}
	go cm.watch()
	return cm, nil
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// get returns the certificate of the configured domain whatever SNI the
// peer sent — like a web server's default certificate — so probes without
// SNI or with a random name see the same site.
func (cm *certManager) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), cm.domain) {
		h := *hello
		h.ServerName = cm.domain
		hello = &h
	}
	return cm.m.GetCertificate(hello)
}

func (cm *certManager) fetch() (*tls.Certificate, error) {
	return cm.get(&tls.ClientHelloInfo{
		ServerName:        cm.domain,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	})
}

// watch obtains the certificate at startup (not on a visitor's handshake),
// retries with backoff until it succeeds, then checks it daily. A due
// renewal is performed by autocert during these checks as well.
func (cm *certManager) watch() {
	for attempt := 0; ; attempt++ {
		cert, err := cm.fetch()
		if err != nil {
			wait := min(time.Duration(1<<min(attempt, 6))*30*time.Second, 30*time.Minute)
			slog.Error("certificate not obtained yet; check that the domain points to this server and ports 80/443 are reachable",
				"domain", cm.domain, "err", err, "retry_in", wait)
			time.Sleep(wait)
			continue
		}
		attempt = 0
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			slog.Info("certificate ready", "domain", cm.domain,
				"expires", leaf.NotAfter.Format(time.DateOnly),
				"renews_after", leaf.NotAfter.Add(-cm.m.RenewBefore).Format(time.DateOnly))
		}
		time.Sleep(24 * time.Hour)
	}
}

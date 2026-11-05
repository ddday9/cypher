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

// newACME returns a GetCertificate function backed by autocert. Every
// handshake gets the certificate of the configured domain, whatever SNI the
// peer sent — like a web server's default certificate — so probes without
// SNI or with a random name see the same site.
func newACME(cfg *config.ACMEConfig, resolve func(string) string) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
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
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cache),
		Email:      cfg.Email,
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
	get := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), domain) {
			h := *hello
			h.ServerName = domain
			hello = &h
		}
		return m.GetCertificate(hello)
	}
	// Obtain the certificate now rather than on the first visitor's handshake.
	go func() {
		for attempt := 0; ; attempt++ {
			_, err := get(&tls.ClientHelloInfo{
				ServerName:        domain,
				CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
				SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
				SupportedCurves:   []tls.CurveID{tls.CurveP256},
				SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			})
			if err == nil {
				slog.Info("certificate ready", "domain", domain)
				return
			}
			wait := min(time.Duration(1<<min(attempt, 6))*30*time.Second, 30*time.Minute)
			slog.Error("certificate not obtained yet; check that the domain points to this server and port 443 is reachable",
				"domain", domain, "err", err, "retry_in", wait)
			time.Sleep(wait)
		}
	}()
	return get, nil
}

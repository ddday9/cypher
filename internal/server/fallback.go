package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"golang.org/x/net/http2"
)

// fallback serves an ordinary website to anyone who is not a valid client:
// browsers, crawlers and active probes all see the same thing a normal
// HTTPS site would show.
type fallback struct {
	handler http.Handler
	h1      *http.Server
	h2      *http2.Server
	ln      *chanListener
}

func newFallback(cfg config.FallbackConfig) (*fallback, error) {
	var h http.Handler
	switch {
	case cfg.Proxy != "":
		u, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("fallback.proxy: %w", err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		base := rp.Director
		rp.Director = func(r *http.Request) {
			base(r)
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		h = rp
	case cfg.Dir != "":
		h = http.FileServer(http.Dir(cfg.Dir))
	default:
		h = http.HandlerFunc(defaultPage)
	}
	f := &fallback{
		handler: h,
		ln:      newChanListener(),
	}
	f.h1 = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          nil,
	}
	f.h2 = &http2.Server{IdleTimeout: 120 * time.Second}
	go f.h1.Serve(f.ln)
	return f, nil
}

// serve hands a TLS connection, plus bytes already read from it, to the
// website. It returns once HTTP/2 connections finish; HTTP/1 connections are
// served asynchronously.
func (f *fallback) serve(conn *tls.Conn, prefix []byte) {
	conn.SetDeadline(time.Time{})
	c := &netx.PrefixConn{Conn: conn, Prefix: prefix}
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		f.h2.ServeConn(c, &http2.ServeConnOpts{Handler: f.handler, BaseConfig: f.h1})
		conn.Close()
		return
	}
	f.ln.push(c)
}

func (f *fallback) close() {
	f.h1.Close()
}

const defaultHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>
</head>
<body>
<h1>Welcome</h1>
<p>This site is under construction. Please check back later.</p>
</body>
</html>
`

func defaultPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, defaultHTML)
}

// chanListener is a net.Listener fed by push.
type chanListener struct {
	ch     chan net.Conn
	done   chan struct{}
	closer sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closer.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

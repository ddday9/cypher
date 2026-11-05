package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/netx"
)

// hopHeaders must not be forwarded by a proxy (RFC 9110 §7.6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func (in *Inbound) handleHTTP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ctx = netx.WithSource(ctx, "tcp", netx.AddrPortOf(conn.RemoteAddr()))
	br := bufio.NewReader(conn)

	var upstream net.Conn
	var upstreamReader *bufio.Reader
	var upstreamHost string
	defer func() {
		if upstream != nil {
			upstream.Close()
		}
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			in.handleConnect(ctx, conn, br, req)
			return
		}

		// Plain HTTP proxy request with an absolute URI.
		if req.URL.Scheme != "http" || req.URL.Host == "" {
			httpError(conn, http.StatusBadRequest)
			return
		}
		hostport := req.URL.Host
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			hostport = net.JoinHostPort(strings.Trim(hostport, "[]"), "80")
		}
		if upstream == nil || upstreamHost != hostport {
			if upstream != nil {
				upstream.Close()
			}
			dest, err := netx.ParseDestination("tcp", hostport)
			if err != nil {
				httpError(conn, http.StatusBadRequest)
				return
			}
			upstream, err = in.dial(ctx, dest)
			if err != nil {
				httpError(conn, dialHTTPStatus(err))
				return
			}
			upstreamReader = bufio.NewReader(upstream)
			upstreamHost = hostport
		}

		for _, h := range hopHeaders {
			req.Header.Del(h)
		}
		req.RequestURI = ""
		if err := req.Write(upstream); err != nil {
			return
		}
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			httpError(conn, http.StatusBadGateway)
			return
		}
		keepAlive := !resp.Close && !req.Close
		for _, h := range hopHeaders {
			if h != "Transfer-Encoding" {
				resp.Header.Del(h)
			}
		}
		err = resp.Write(conn)
		resp.Body.Close()
		if err != nil || !keepAlive {
			return
		}
	}
}

func (in *Inbound) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request) {
	dest, err := netx.ParseDestination("tcp", req.Host)
	if err != nil {
		httpError(conn, http.StatusBadRequest)
		return
	}
	target, err := in.dial(ctx, dest)
	if err != nil {
		httpError(conn, dialHTTPStatus(err))
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		target.Close()
		return
	}
	var c net.Conn = conn
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		c = &netx.PrefixConn{Conn: conn, Prefix: append([]byte(nil), b...)}
	}
	netx.Relay(c, target)
}

func dialHTTPStatus(err error) int {
	if errors.Is(err, client.ErrBlocked) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func httpError(conn net.Conn, code int) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
}

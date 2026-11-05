package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
)

// Routes a request can take on the server.
const (
	routeDirect = "direct" // the server connects itself
	routeBlock  = "block"
	routeExit   = "exit" // relay: through the upstream exit server
)

// UpstreamOutbound turns an upstream section into a cypher outbound config.
func UpstreamOutbound(u *config.UpstreamConfig) (config.OutboundConfig, error) {
	oc := u.OutboundConfig
	if u.Link != "" {
		l, err := links.Parse(u.Link)
		if err != nil {
			return oc, fmt.Errorf("server.upstream.link: %w", err)
		}
		if oc.Server == "" {
			oc.Server = l.Server
		}
		if oc.Key == "" {
			oc.Key = l.Key
		}
		if oc.ServerName == "" {
			oc.ServerName = l.ServerName
		}
		if oc.Fingerprint == "" {
			oc.Fingerprint = l.Fingerprint
		}
		if oc.AntiFreeze == "" {
			oc.AntiFreeze = l.AntiFreeze
		}
		if oc.ExitPublicKey == "" {
			oc.ExitPublicKey = l.ExitPublicKey
		}
		oc.SingleConnection = oc.SingleConnection || l.Single
	}
	if oc.Server == "" || oc.Key == "" {
		return oc, errors.New("server.upstream: set link, or server and key")
	}
	oc.Tag, oc.Type = "exit", "cypher"
	return oc, nil
}

func newExit(u *config.UpstreamConfig, resolve func(string) string) (*client.Cypher, error) {
	oc, err := UpstreamOutbound(u)
	if err != nil {
		return nil, err
	}
	// The exit's public key is only used for links printed on the relay;
	// the relay itself never encrypts end to end.
	oc.ExitKey, oc.ExitPublicKey, oc.HideDestinations = "", "", false
	o, err := client.New(oc, resolve)
	if err != nil {
		return nil, fmt.Errorf("server.upstream: %w", err)
	}
	o.(*client.Cypher).NeedCaps()
	slog.Info("relay mode: traffic routed to \"exit\" goes to the upstream server", "exit", oc.Server)
	return o.(*client.Cypher), nil
}

// route picks direct, block or exit for a destination of user.
func (s *Server) route(user string, dest netx.Destination) string {
	if r := s.router.Load(); r != nil {
		return r.Route(context.Background(), routerMetadata(user, dest))
	}
	return s.defaultRoute()
}

func (s *Server) defaultRoute() string {
	if s.exit != nil {
		return routeExit
	}
	return routeDirect
}

// dialExit connects to dest through the exit server.
func (s *Server) dialExit(ctx context.Context, dest netx.Destination) (net.Conn, byte) {
	c, err := s.exit.Dial(ctx, dest)
	if err == nil {
		return c, protocol.StatusOK
	}
	var se protocol.StatusError
	if errors.As(err, &se) {
		return nil, byte(se)
	}
	slog.Warn("exit server unreachable", "err", err)
	return nil, protocol.StatusUnreachable
}

// handleRelayE2E serves a request from a client that can encrypt for the
// exit. The relay sees the destination and routes it: streams it handles
// itself continue in the clear; streams for the exit pass through
// encrypted, unless the exit is too old for that.
func (s *Server) handleRelayE2E(st net.Conn, user *protocol.User, req protocol.Request) {
	req.Cmd &^= protocol.CmdFlagE2E
	if req.Cmd != protocol.CmdTCP && req.Cmd != protocol.CmdUDP {
		st.Write([]byte{protocol.StatusFailure})
		return
	}
	route := s.route(user.Name, req.Dest)
	if route == routeExit {
		ctx, cancel := context.WithTimeout(context.Background(), 2*dialTimeout)
		ok := s.exit.SupportsE2E(ctx)
		cancel()
		if ok {
			s.forwardE2E(st, user)
			return
		}
		slog.Debug("exit does not support end-to-end encryption; relaying in the clear", "user", user.Name)
	}
	if err := protocol.SkipFrame(st); err != nil { // the handshake meant for the exit
		return
	}
	s.serve(st, user, req, route, plainAnswer(st))
}

// forwardE2E passes an end-to-end encrypted stream to the exit unread.
func (s *Server) forwardE2E(st net.Conn, user *protocol.User) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*dialTimeout)
	up, err := s.exit.OpenE2E(ctx)
	cancel()
	if err != nil {
		status := protocol.StatusUnreachable
		if errors.Is(err, client.ErrNoE2E) {
			status = protocol.StatusFailure
		}
		slog.Debug("e2e forward failed", "user", user.Name, "err", err)
		st.Write([]byte{status})
		return
	}
	st.SetDeadline(time.Time{})
	slog.Debug("e2e stream to the exit", "user", user.Name)
	netx.Relay(st, up)
}

// handleE2E terminates an end-to-end encrypted stream: this server is the
// exit. The user is the one inside (the client's exit key), not the relay
// that carried it.
func (s *Server) handleE2E(st net.Conn, via *protocol.User) {
	if s.e2eKey == nil {
		st.Write([]byte{protocol.StatusFailure})
		return
	}
	if _, err := st.Write([]byte{protocol.StatusE2E}); err != nil {
		return
	}
	r, err := protocol.AcceptE2E(st, *s.e2eKey, s.auth)
	if err != nil {
		slog.Debug("e2e handshake failed", "via", via.Name, "err", err)
		return
	}
	user := r.User
	s.track(user.Key, st)
	defer s.untrack(user.Key, st)
	slog.Debug("e2e stream", "user", user.Name, "via", via.Name)
	s.serve(st, user, r.Request, s.route(user.Name, r.Request.Dest), r.Answer)
}

// LoadOrCreateE2EKey reads the exit's static key from path, creating it if
// it does not exist.
func LoadOrCreateE2EKey(path string) (protocol.E2EKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		priv, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return protocol.E2EKey{}, fmt.Errorf("%s: %w", path, err)
		}
		return protocol.E2EKeyFromPrivate(priv)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return protocol.E2EKey{}, err
	}
	var priv [32]byte
	rand.Read(priv[:])
	k, err := protocol.E2EKeyFromPrivate(priv[:])
	if err != nil {
		return k, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return k, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.RawURLEncoding.EncodeToString(priv[:])+"\n"), 0o640); err != nil {
		return k, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return k, err
	}
	slog.Info("created end-to-end encryption key", "file", path)
	return LoadOrCreateE2EKey(path) // whoever won a race, use the file
}

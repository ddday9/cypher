package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/router"
)

// SetRouting applies server-side rules (same format as the client's
// "routing" section). Outbounds are "direct" and "block"; inboundTag
// matches the user name, so rules can target one user.
func (s *Server) SetRouting(rc config.RoutingConfig, resolve func(string) string) error {
	if len(rc.Rules) == 0 {
		s.router.Store(nil)
		return nil
	}
	site, ip := rc.Geosite, rc.Geoip
	if site == "" {
		site = "geosite.dat"
	}
	if ip == "" {
		ip = "geoip.dat"
	}
	if rc.Default == "" {
		rc.Default = "direct"
	}
	r, err := router.New(rc, "direct", router.NewGeoLoader(resolve(site), resolve(ip)))
	if err != nil {
		return err
	}
	for _, tag := range append([]string{r.DefaultTag()}, r.OutboundTags()...) {
		if tag != "direct" && tag != "block" {
			return fmt.Errorf("server routing: outbound must be \"direct\" or \"block\", got %q", tag)
		}
	}
	s.router.Store(r)
	slog.Info("server routing rules applied", "rules", len(rc.Rules))
	return nil
}

// blocked reports whether the server rules forbid this destination for user.
func (s *Server) blocked(user string, dest netx.Destination) bool {
	r := s.router.Load()
	if r == nil {
		return false
	}
	return r.Route(context.Background(), router.Metadata{InboundTag: user, Dest: dest}) == "block"
}

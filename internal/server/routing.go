package server

import (
	"fmt"
	"log/slog"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/router"
)

// SetRouting applies server-side rules (same format as the client's
// "routing" section). Outbounds are "direct", "block" and, on a relay,
// "exit"; inboundTag matches the user name, so rules can target one user.
// Without rules everything goes direct (or to the exit on a relay).
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
		rc.Default = s.defaultRoute()
	}
	r, err := router.New(rc, s.defaultRoute(), router.NewGeoLoader(resolve(site), resolve(ip)))
	if err != nil {
		return err
	}
	for _, tag := range append([]string{r.DefaultTag()}, r.OutboundTags()...) {
		switch {
		case tag == routeDirect || tag == routeBlock:
		case tag == routeExit && s.exit != nil:
		case tag == routeExit:
			return fmt.Errorf("server routing: outbound \"exit\" needs server.upstream (relay mode)")
		default:
			return fmt.Errorf("server routing: outbound must be \"direct\", \"block\" or \"exit\", got %q", tag)
		}
	}
	s.router.Store(r)
	slog.Info("server routing rules applied", "rules", len(rc.Rules), "default", r.DefaultTag())
	return nil
}

func routerMetadata(user string, dest netx.Destination) router.Metadata {
	return router.Metadata{InboundTag: user, Dest: dest}
}

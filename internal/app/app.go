// Package app wires configuration into a running client or server.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/inbound"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/router"
	"github.com/ddday9/cypher/internal/server"
)

// Run starts a server or a client depending on the config and blocks until
// ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config) error {
	if cfg.Server != nil {
		if len(cfg.Inbounds) > 0 || len(cfg.Outbounds) > 0 {
			return errors.New(`config has both "server" and inbounds/outbounds; use separate files`)
		}
		s, err := server.New(cfg.Server, cfg.Resolve)
		if err != nil {
			return err
		}
		return s.ListenAndServe(ctx)
	}
	c, err := NewClient(cfg)
	if err != nil {
		return err
	}
	return c.Run(ctx)
}

// Client routes local inbound connections to outbounds.
type Client struct {
	inbounds  []*inbound.Inbound
	outbounds map[string]client.Outbound
	router    *router.Router
}

// NewClient builds a client from config.
func NewClient(cfg *config.Config) (*Client, error) {
	if len(cfg.Outbounds) == 0 {
		return nil, errors.New("no outbounds configured")
	}
	if len(cfg.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}
	c := &Client{outbounds: map[string]client.Outbound{}}
	for i, oc := range cfg.Outbounds {
		if oc.Tag == "" {
			return nil, fmt.Errorf("outbounds[%d]: tag is required", i)
		}
		if _, dup := c.outbounds[oc.Tag]; dup {
			return nil, fmt.Errorf("duplicate outbound tag %q", oc.Tag)
		}
		o, err := client.New(oc, cfg.Resolve)
		if err != nil {
			return nil, fmt.Errorf("outbound %q: %w", oc.Tag, err)
		}
		c.outbounds[oc.Tag] = o
	}

	rc := cfg.Routing
	geosite, geoip := rc.Geosite, rc.Geoip
	if geosite == "" {
		geosite = "geosite.dat"
	}
	if geoip == "" {
		geoip = "geoip.dat"
	}
	geo := router.NewGeoLoader(cfg.Resolve(geosite), cfg.Resolve(geoip))
	r, err := router.New(rc, cfg.Outbounds[0].Tag, geo)
	if err != nil {
		return nil, err
	}
	c.router = r
	tags := []string{r.DefaultTag()}
	tags = append(tags, r.OutboundTags()...)
	for _, t := range tags {
		if _, ok := c.outbounds[t]; !ok {
			return nil, fmt.Errorf("routing refers to unknown outbound %q", t)
		}
	}

	for i, ic := range cfg.Inbounds {
		if ic.Tag == "" {
			ic.Tag = fmt.Sprintf("%s-%d", strings.ToLower(ic.Type), i)
		}
		in, err := inbound.New(ic, c)
		if err != nil {
			return nil, err
		}
		c.inbounds = append(c.inbounds, in)
	}
	return c, nil
}

// Dispatch implements inbound.Dispatcher.
func (c *Client) Dispatch(ctx context.Context, inboundTag string, dest netx.Destination) (net.Conn, error) {
	tag := c.router.Route(ctx, router.Metadata{InboundTag: inboundTag, Dest: dest})
	o := c.outbounds[tag]
	conn, err := o.Dial(ctx, dest)
	if err != nil {
		return nil, fmt.Errorf("%s via %s: %w", dest, tag, err)
	}
	slog.Info("connect", "dest", dest.String(), "outbound", tag)
	return conn, nil
}

// Run serves all inbounds until ctx is cancelled or one of them fails.
func (c *Client) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		for _, o := range c.outbounds {
			o.Close()
		}
	}()
	var wg sync.WaitGroup
	errs := make(chan error, len(c.inbounds))
	for _, in := range c.inbounds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := in.Serve(ctx); err != nil {
				errs <- err
				cancel()
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs
}

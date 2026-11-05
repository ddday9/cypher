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
	"sync/atomic"
	"time"

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
		if cfg.Path != "" {
			go watchServerConfig(ctx, cfg.Path, s, reloadInterval)
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
	cfg       *config.Config
	inbounds  []*inbound.Inbound
	outbounds map[string]client.Outbound
	router    atomic.Pointer[router.Router]

	traffic Traffic

	reloadMu sync.Mutex
	watched  []string // files whose changes trigger a routing reload
}

// NewClient builds a client from config.
func NewClient(cfg *config.Config) (*Client, error) {
	if len(cfg.Outbounds) == 0 {
		return nil, errors.New("no outbounds configured")
	}
	if len(cfg.Inbounds) == 0 {
		return nil, errors.New("no inbounds configured")
	}
	c := &Client{cfg: cfg, outbounds: map[string]client.Outbound{}}
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

	r, watched, err := c.buildRouter(cfg)
	if err != nil {
		return nil, err
	}
	c.router.Store(r)
	c.watched = watched

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
	tag := c.router.Load().Route(ctx, router.Metadata{InboundTag: inboundTag, Dest: dest})
	o := c.outbounds[tag]
	conn, err := o.Dial(ctx, dest)
	if err != nil {
		return nil, fmt.Errorf("%s via %s: %w", dest, tag, err)
	}
	slog.Info("connect", "dest", dest.String(), "outbound", tag)
	return &countingConn{Conn: conn, t: &c.traffic}, nil
}

func (c *Client) hasTUN() bool {
	for _, in := range c.inbounds {
		if in.Type() == "tun" {
			return true
		}
	}
	return false
}

// RoutePacket implements inbound.Dispatcher.
func (c *Client) RoutePacket(ctx context.Context, inboundTag string, dest netx.Destination) string {
	dest.Network = "udp"
	return c.router.Load().Route(ctx, router.Metadata{InboundTag: inboundTag, Dest: dest})
}

// ListenPacket implements inbound.Dispatcher.
func (c *Client) ListenPacket(ctx context.Context, tag string, dest netx.Destination) (netx.PacketConn, error) {
	o, ok := c.outbounds[tag]
	if !ok {
		return nil, fmt.Errorf("unknown outbound %q", tag)
	}
	pc, err := o.ListenPacket(ctx, dest)
	if err != nil {
		return nil, fmt.Errorf("udp %s via %s: %w", dest, tag, err)
	}
	slog.Info("udp", "dest", dest.String(), "outbound", tag)
	return &countingPacketConn{PacketConn: pc, t: &c.traffic}, nil
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
	if c.hasTUN() {
		// Resolve server names now: once TUN routes are in place, DNS itself
		// goes through the tunnel, which would need the server first.
		for _, o := range c.outbounds {
			if p, ok := o.(interface{ PinServer(context.Context) error }); ok {
				pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
				err := p.PinServer(pctx)
				pcancel()
				if err != nil {
					return err
				}
			}
		}
	}
	go c.watch(ctx, reloadInterval)
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

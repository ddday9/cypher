// Package inbound implements local proxy listeners: SOCKS5 and HTTP.
package inbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
)

// Dispatcher routes a destination to an outbound and dials it.
type Dispatcher interface {
	Dispatch(ctx context.Context, inboundTag string, dest netx.Destination) (net.Conn, error)
	// RoutePacket picks the outbound for a UDP destination.
	RoutePacket(ctx context.Context, inboundTag string, dest netx.Destination) string
	// ListenPacket opens a UDP association on the given outbound.
	ListenPacket(ctx context.Context, outboundTag string, dest netx.Destination) (netx.PacketConn, error)
}

// Inbound is a local listener.
type Inbound struct {
	tag     string
	typ     string
	listen  string
	handler func(ctx context.Context, conn net.Conn)
	tun     *tunInbound
	d       Dispatcher
}

// Type returns the inbound type ("socks", "http", "tun").
func (in *Inbound) Type() string { return in.typ }

// New creates an inbound from config.
func New(cfg config.InboundConfig, d Dispatcher) (*Inbound, error) {
	in := &Inbound{tag: cfg.Tag, typ: strings.ToLower(cfg.Type), listen: cfg.Listen, d: d}
	switch in.typ {
	case "socks", "socks5":
		in.handler = in.handleSOCKS
	case "http":
		in.handler = in.handleHTTP
	case "tun":
		t, err := newTUN(in, cfg)
		if err != nil {
			return nil, err
		}
		in.tun = t
		return in, nil
	default:
		return nil, fmt.Errorf("unknown inbound type %q", cfg.Type)
	}
	if in.listen == "" {
		return nil, fmt.Errorf("inbound %q: listen is required", cfg.Tag)
	}
	return in, nil
}

// Serve listens until ctx is cancelled.
func (in *Inbound) Serve(ctx context.Context) error {
	if in.tun != nil {
		return in.tun.serve(ctx)
	}
	ln, err := net.Listen("tcp", in.listen)
	if err != nil {
		return err
	}
	slog.Info("inbound listening", "tag", in.tag, "type", in.typ, "addr", ln.Addr().String())
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}
		go in.handler(ctx, c)
	}
}

func (in *Inbound) dial(ctx context.Context, dest netx.Destination) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := in.d.Dispatch(dctx, in.tag, dest)
	if err != nil {
		slog.Debug("dial failed", "inbound", in.tag, "dest", dest.String(), "err", err)
	}
	return conn, err
}

// Package engine runs the client core on behalf of a user interface: start,
// stop, status, traffic counters and recent log lines.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/ddday9/cypher/internal/app"
	"github.com/ddday9/cypher/internal/config"
)

// Status of the engine.
type Status string

const (
	StatusStopped    Status = "stopped"
	StatusConnecting Status = "connecting"
	StatusConnected  Status = "connected"
)

// Engine owns one running client at a time.
type Engine struct {
	mu      sync.Mutex
	status  Status
	client  *app.Client
	cancel  context.CancelFunc
	done    chan struct{}
	since   time.Time
	lastErr string
}

// New creates a stopped engine.
func New() *Engine { return &Engine{status: StatusStopped} }

// startupGrace is how long Start waits for immediate failures (a busy port,
// TUN creation) before reporting success.
var startupGrace = 700 * time.Millisecond

// Start runs a client with cfg. It stops a running one first.
func (e *Engine) Start(cfg *config.Config) error {
	e.Stop()
	e.mu.Lock()
	e.status, e.lastErr = StatusConnecting, ""
	e.mu.Unlock()

	c, err := app.NewClient(cfg)
	if err != nil {
		e.fail(err)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		defer close(done)
		errc <- c.Run(ctx)
	}()
	select {
	case err := <-errc:
		cancel()
		if err == nil {
			err = errors.New("client stopped unexpectedly")
		}
		e.fail(err)
		return err
	case <-time.After(startupGrace):
	}
	e.mu.Lock()
	e.client, e.cancel, e.done = c, cancel, done
	e.status, e.since = StatusConnected, time.Now()
	e.mu.Unlock()
	go func() { // a later failure (e.g. TUN removed) stops the engine
		if err := <-errc; err != nil && ctx.Err() == nil {
			slog.Error("client stopped", "err", err)
			e.mu.Lock()
			if e.done == done {
				e.status, e.lastErr, e.client = StatusStopped, err.Error(), nil
			}
			e.mu.Unlock()
		}
	}()
	return nil
}

func (e *Engine) fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status, e.lastErr = StatusStopped, err.Error()
	slog.Error("connect failed", "err", err)
}

// Stop stops the running client and waits for it to exit.
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	e.cancel, e.done, e.client = nil, nil, nil
	e.status = StatusStopped
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			slog.Warn("client did not stop in time")
		}
	}
}

// State is a snapshot for the UI.
type State struct {
	Status Status    `json:"status"`
	Since  time.Time `json:"since"`
	Up     int64     `json:"up"`
	Down   int64     `json:"down"`
	Error  string    `json:"error,omitempty"`
	// AntiFreeze: traffic currently goes over short connections because
	// connection freezes were detected (or the mode is always on).
	AntiFreeze bool `json:"antiFreeze,omitempty"`
}

// State returns the current status and traffic.
func (e *Engine) State() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := State{Status: e.status, Error: e.lastErr}
	if e.client != nil {
		st.Since = e.since
		st.Up, st.Down = e.client.Traffic()
		st.AntiFreeze = e.client.AntiFreezeActive()
	}
	return st
}

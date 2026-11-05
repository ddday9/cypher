package protocol

import (
	"math/rand/v2"
	"time"

	"github.com/xtaci/smux"
)

// Keepalive timing. smux's built-in keepalive (disabled in MuxConfig) sends
// a frame every 15 s exactly; a fixed heartbeat on a long-lived connection
// is one of the features DPI vendors use to tell tunnels from browsers.
// Here the interval is random, and a session without streams stays silent
// when the peer allows it, like an idle HTTP/2 connection.
//
// Older peers close a session after 60 s without data, so the interval
// stays below that.
var (
	KeepAliveMin = 10 * time.Second
	KeepAliveMax = 40 * time.Second
)

// KeepAlive keeps sess alive until it closes.
//
//   - nop sends one keepalive frame;
//   - always reports whether to send keepalives even when the session has
//     no streams (the peer is an older version that times out quiet sessions);
//   - lastRead reports when the peer last sent anything; the session is
//     closed when that is longer ago than timeout (with open streams) or
//     idleTimeout (without). Zero disables the check.
func KeepAlive(sess *smux.Session, nop func() error, always func() bool, lastRead func() time.Time, timeout, idleTimeout time.Duration) {
	lo, hi := KeepAliveMin, KeepAliveMax
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		t.Reset(lo + rand.N(hi-lo+1))
		select {
		case <-sess.CloseChan():
			return
		case <-t.C:
		}
		streams := sess.NumStreams() > 0
		if streams || always() {
			if nop() != nil {
				sess.Close()
				return
			}
		}
		limit := idleTimeout
		if streams {
			limit = timeout
		}
		if limit > 0 && lastRead != nil && time.Since(lastRead()) > limit {
			sess.Close()
			return
		}
	}
}

// WriteKeepAlive appends a keepalive frame to the session's stream.
func (s *Session) WriteKeepAlive() error {
	_, err := s.Write(smuxNOP)
	return err
}

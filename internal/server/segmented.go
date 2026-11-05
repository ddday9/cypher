package server

import (
	"log/slog"
	"time"

	"github.com/ddday9/cypher/internal/protocol"
	"github.com/xtaci/smux"
)

// segEntry is a live anti-freeze session.
type segEntry struct {
	sess *protocol.Session
	key  protocol.Key
}

// sessionIdle closes an anti-freeze session that had no carrier this long.
var sessionIdle = 2 * time.Minute

// handleSegmented serves a connection that carries (part of) an anti-freeze
// session: either the first carrier of a new session, or a later one.
func (s *Server) handleSegmented(rc *protocol.RecordConn, user *protocol.User, ext *protocol.Ext, remote string) {
	if ext.Flags&protocol.FlagAttach != 0 {
		s.segMu.Lock()
		e := s.segs[ext.Session]
		s.segMu.Unlock()
		if e == nil || e.key != user.Key || e.sess.Closed() {
			rc.Close() // unknown session: the client will start a new one
			return
		}
		e.sess.AttachSeq(rc, ext.Seq)
		return
	}

	sess := protocol.NewSession(ext.Session, protocol.DefaultBudget)
	if err := rc.WriteControl(protocol.CtlHello, protocol.Hello(serverCaps)); err != nil {
		rc.Close()
		return
	}
	sess.Attach(rc)
	s.segMu.Lock()
	if old := s.segs[ext.Session]; old != nil {
		old.sess.Close()
	}
	s.segs[ext.Session] = &segEntry{sess: sess, key: user.Key}
	s.segMu.Unlock()
	defer func() {
		s.segMu.Lock()
		if e := s.segs[ext.Session]; e != nil && e.sess == sess {
			delete(s.segs, ext.Session)
		}
		s.segMu.Unlock()
		sess.Close()
	}()
	slog.Info("client connected", "user", user.Name, "remote", remote, "protocol", 2, "mode", "anti-freeze")

	go func() { // drop sessions whose client went away
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		last := time.Now()
		for range t.C {
			if sess.Closed() {
				return
			}
			if sess.HasCarrier() {
				last = time.Now()
			} else if time.Since(last) > sessionIdle {
				sess.Close()
				return
			}
		}
	}()

	ms, err := smux.Server(sess, protocol.MuxConfig())
	if err != nil {
		return
	}
	defer ms.Close()
	// The session itself notices a lost client (no carrier for sessionIdle).
	go protocol.KeepAlive(ms, sess.WriteKeepAlive, func() bool { return true }, nil, 0, 0)
	s.track(user.Key, ms)
	defer s.untrack(user.Key, ms)
	for {
		st, err := ms.AcceptStream()
		if err != nil {
			slog.Debug("session closed", "user", user.Name, "err", err)
			return
		}
		go s.handleStream(st, user)
	}
}

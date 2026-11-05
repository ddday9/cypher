package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Session is a reliable byte stream carried by a sequence of short
// connections ("carriers"). It exists because some censors freeze a TCP
// connection once ~16 KB went through it: a session moves to a fresh
// carrier before that point, and re-sends whatever a frozen carrier lost.
//
// On a carrier, data travels in CtlData records (offset, "more" flag,
// payload) and is confirmed with CtlAck (cumulative offset). Each side
// sends at most Budget bytes per carrier, then announces CtlDrain; the
// client opens the next carrier. smux runs on top of a Session exactly as
// on a plain connection.
type Session struct {
	ID     [16]byte
	Budget int // bytes this side sends per carrier (payload and overhead)

	// NeedCarrier is called (without locks held) when the client side should
	// open a new carrier: budget spent, peer drained, or a stall.
	NeedCarrier func(reason string)

	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
	err    error

	// send side
	sendBuf  []byte // unacknowledged data, starting at ackedOff
	ackedOff uint64
	sendOff  uint64 // next offset to send on the current carrier
	ackDue   bool   // an ACK should be sent
	lastAck  time.Time

	// receive side
	recvOff    uint64
	readBuf    []byte
	unacked    int // bytes received since the last ACK we sent
	lastRecv   time.Time
	peerMore   bool // the peer said it has more queued
	lastSendAt time.Time

	cur      *carrier
	carriers int    // carriers attached so far
	lastSeq  uint32 // highest client carrier number attached (server side)

	bytesIn, bytesOut int64
}

type carrier struct {
	rc       *RecordConn
	seq      int
	sent     int
	recvd    int
	drained  bool // we will not send on it any more
	dead     bool
	attached time.Time
}

const (
	sessMaxBuffer  = 1 << 20 // unacknowledged bytes before Write blocks
	sessChunk      = 4096
	sessAckEvery   = 4096
	sessAckDelay   = 30 * time.Millisecond
	recordOverhead = 4 + 1 + 32 + 29 // record header, type, padding, TLS record (approx.)
	// DefaultBudget keeps a carrier well under the ~16 KB freeze threshold
	// reported for Russian mobile networks (the TLS handshake also counts).
	DefaultBudget = 8 * 1024
)

// ErrSessionClosed is returned by a closed session.
var ErrSessionClosed = errors.New("session closed")

// NewSession creates a session; attach carriers with Attach.
func NewSession(id [16]byte, budget int) *Session {
	if budget <= 0 {
		budget = DefaultBudget
	}
	s := &Session{ID: id, Budget: budget, lastAck: time.Now(), lastRecv: time.Now()}
	s.cond = sync.NewCond(&s.mu)
	go s.sender()
	go s.ticker()
	return s
}

// AttachSeq attaches a carrier numbered seq by the client, unless a newer
// one is already attached (connections can finish their handshakes out of
// order). It reports whether rc was attached.
func (s *Session) AttachSeq(rc *RecordConn, seq uint32) bool {
	s.mu.Lock()
	if seq != 0 && seq <= s.lastSeq {
		s.mu.Unlock()
		rc.Close()
		return false
	}
	s.lastSeq = seq
	s.mu.Unlock()
	s.Attach(rc)
	return true
}

// Attach makes rc the carrier for sending. Data not yet acknowledged is
// sent again on it; the previous carrier is closed.
func (s *Session) Attach(rc *RecordConn) {
	c := &carrier{rc: rc, attached: time.Now()}
	rc.SetControlHandler(func(typ byte, body []byte) { s.onControl(c, typ, body) })
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		rc.Close()
		return
	}
	old := s.cur
	s.carriers++
	c.seq = s.carriers
	s.cur = c
	s.sendOff = s.ackedOff // resend everything the peer has not confirmed
	s.ackDue = true        // tell the peer where to resume
	s.cond.Broadcast()
	s.mu.Unlock()
	if old != nil {
		old.rc.Close()
	}
	go func() { // pump the carrier: control records are handled by onControl
		buf := make([]byte, 512)
		for {
			if _, err := rc.Read(buf); err != nil {
				s.carrierDead(c)
				return
			}
		}
	}()
}

// WantsCarrier reports whether the client should open a carrier now: none
// is usable, it is spent, or the peer has nearly spent its budget on it.
func (s *Session) WantsCarrier() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cur
	return !s.closed && (c == nil || c.dead || c.drained || c.recvd > s.Budget*3/4)
}

// Carriers returns how many carriers the session has used.
func (s *Session) Carriers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.carriers
}

// HasCarrier reports whether a usable carrier is attached.
func (s *Session) HasCarrier() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur != nil && !s.cur.dead
}

func (s *Session) carrierDead(c *carrier) {
	s.mu.Lock()
	c.dead = true
	need := s.cur == c && !s.closed
	// Closed right away with nothing received: the peer refused it.
	rejected := c.recvd == 0 && time.Since(c.attached) < time.Second
	s.cond.Broadcast()
	s.mu.Unlock()
	if need && s.NeedCarrier != nil {
		if rejected {
			s.NeedCarrier(CarrierRejected)
		} else {
			s.NeedCarrier("carrier closed")
		}
	}
}

// CarrierRejected is the NeedCarrier reason for a carrier the peer closed
// immediately (for example a server that no longer knows the session).
const CarrierRejected = "carrier rejected"

func (s *Session) onControl(c *carrier, typ byte, body []byte) {
	var need string
	s.mu.Lock()
	switch typ {
	case CtlData:
		if len(body) < 9 {
			break
		}
		off := binary.BigEndian.Uint64(body)
		more := body[8] != 0
		data := body[9:]
		c.recvd += len(data) + recordOverhead
		s.lastRecv = time.Now()
		s.peerMore = more
		end := off + uint64(len(data))
		if off <= s.recvOff && end > s.recvOff {
			fresh := data[s.recvOff-off:]
			s.readBuf = append(s.readBuf, fresh...)
			s.recvOff = end
			s.unacked += len(fresh)
			s.bytesIn += int64(len(fresh))
			if s.unacked >= sessAckEvery {
				s.ackDue = true
			}
			s.cond.Broadcast()
		}
		// Prepare the next carrier before the server runs out of budget.
		if s.NeedCarrier != nil && c == s.cur && c.recvd > s.Budget*3/4 {
			need = "peer budget nearly spent"
		}
	case CtlAck:
		if len(body) < 8 {
			break
		}
		c.recvd += 8 + recordOverhead
		off := binary.BigEndian.Uint64(body)
		if off > s.ackedOff && off <= s.ackedOff+uint64(len(s.sendBuf)) {
			s.sendBuf = s.sendBuf[off-s.ackedOff:]
			s.ackedOff = off
			s.lastAck = time.Now()
			if s.sendOff < s.ackedOff {
				s.sendOff = s.ackedOff
			}
			s.cond.Broadcast()
		}
	case CtlDrain:
		if s.NeedCarrier != nil && c == s.cur {
			need = "peer drained"
		}
	}
	s.mu.Unlock()
	if need != "" {
		s.NeedCarrier(need)
	}
}

// sender transmits queued data and ACKs on the current carrier.
func (s *Session) sender() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		for !s.closed && !s.canSend() {
			s.cond.Wait()
		}
		if s.closed {
			return
		}
		c := s.cur
		var typ byte
		var body []byte
		if s.ackDue {
			typ, body = CtlAck, binary.BigEndian.AppendUint64(nil, s.recvOff)
			s.ackDue, s.unacked = false, 0
		} else {
			start := int(s.sendOff - s.ackedOff)
			n := min(len(s.sendBuf)-start, sessChunk, s.Budget-c.sent-recordOverhead*2)
			if n <= 0 {
				s.drain(c)
				continue
			}
			more := start+n < len(s.sendBuf)
			body = binary.BigEndian.AppendUint64(make([]byte, 0, 9+n), s.sendOff)
			if more {
				body = append(body, 1)
			} else {
				body = append(body, 0)
			}
			body = append(body, s.sendBuf[start:start+n]...)
			typ = CtlData
			s.sendOff += uint64(n)
			s.bytesOut += int64(n)
		}
		c.sent += len(body) + recordOverhead
		s.lastSendAt = time.Now()
		s.mu.Unlock()
		err := c.rc.WriteControl(typ, body)
		s.mu.Lock()
		if err != nil {
			c.dead = true
			continue
		}
		if c.sent >= s.Budget-recordOverhead*2 {
			s.drain(c)
		}
	}
}

// canSend: caller holds mu.
func (s *Session) canSend() bool {
	c := s.cur
	if c == nil || c.dead || c.drained {
		return false
	}
	return s.ackDue || s.sendOff < s.ackedOff+uint64(len(s.sendBuf))
}

// drain stops using c for sending. Caller holds mu.
func (s *Session) drain(c *carrier) {
	if c.drained {
		return
	}
	c.drained = true
	rc := c.rc
	need := s.NeedCarrier
	s.mu.Unlock()
	rc.WriteControl(CtlDrain, nil)
	if need != nil {
		need("budget spent")
	}
	s.mu.Lock()
}

// ticker sends delayed ACKs and detects stalls (a frozen carrier).
func (s *Session) ticker() {
	t := time.NewTicker(sessAckDelay)
	defer t.Stop()
	for range t.C {
		var need string
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		if s.unacked > 0 && !s.ackDue {
			s.ackDue = true
			s.cond.Broadcast()
		}
		c := s.cur
		if s.NeedCarrier != nil && c != nil && !c.dead && time.Since(c.attached) > time.Second {
			unackedData := s.ackedOff < s.sendOff
			switch {
			case s.peerMore && time.Since(s.lastRecv) > 1500*time.Millisecond:
				need = "stall: peer data stopped"
			case unackedData && time.Since(s.lastAck) > 2*time.Second && time.Since(s.lastSendAt) > 2*time.Second:
				need = "stall: no acknowledgement"
			}
			if need != "" {
				c.dead = true // stop using it; the next carrier takes over
				s.peerMore = false
				s.lastAck = time.Now()
			}
		}
		s.mu.Unlock()
		if need != "" {
			slog.Debug("session carrier stalled", "reason", need)
			s.NeedCarrier(need)
		}
	}
}

// Read implements io.Reader.
func (s *Session) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.readBuf) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	if len(s.readBuf) == 0 {
		s.readBuf = nil
	}
	return n, nil
}

// Write implements io.Writer; it blocks while too much is unacknowledged.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for len(p) > 0 {
		for !s.closed && len(s.sendBuf) >= sessMaxBuffer {
			s.cond.Wait()
		}
		if s.closed {
			return total, ErrSessionClosed
		}
		n := min(len(p), sessMaxBuffer-len(s.sendBuf))
		s.sendBuf = append(s.sendBuf, p[:n]...)
		p = p[n:]
		total += n
		s.cond.Broadcast()
	}
	return total, nil
}

// Close closes the session and its carrier.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	c := s.cur
	s.cond.Broadcast()
	s.mu.Unlock()
	if c != nil {
		c.rc.Close()
	}
	return nil
}

// Closed reports whether the session is closed.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Traffic returns payload bytes received and sent.
func (s *Session) Traffic() (in, out int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytesIn, s.bytesOut
}

// debugState describes the session for tests.
func (s *Session) debugState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cur
	cs := "none"
	if c != nil {
		cs = fmt.Sprintf("seq=%d sent=%d recvd=%d drained=%v dead=%v", c.seq, c.sent, c.recvd, c.drained, c.dead)
	}
	return fmt.Sprintf("acked=%d sendOff=%d buf=%d recvOff=%d readBuf=%d ackDue=%v peerMore=%v carrier[%s]",
		s.ackedOff, s.sendOff, len(s.sendBuf), s.recvOff, len(s.readBuf), s.ackDue, s.peerMore, cs)
}

package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// End-to-end encryption through a relay (protocol section 8).
//
// A client that reaches the exit server through a relay encrypts each
// stream a second time, for the exit only, so the relay forwards ciphertext
// it cannot read or alter. The handshake is Noise NK: the client knows the
// exit's static public key from the link and authenticates itself inside
// the first message with the usual HMAC auth header of its exit key.
//
// Every Noise message travels as a frame: length (2 bytes, big endian) |
// message. After the handshake, a frame's plaintext is dataLen (2 bytes) |
// data | padding.

var e2eSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

var e2ePrologue = []byte("cypher/v1/e2e")

const (
	e2eMaxFrame   = 65535
	e2eMaxData    = 16 * 1024
	e2eSmallData  = 256
	e2eMaxPadding = 256
)

// E2EKey is the exit server's static key pair.
type E2EKey struct {
	Private, Public []byte
}

// GenerateE2EKey creates a new static key pair.
func GenerateE2EKey() (E2EKey, error) {
	kp, err := e2eSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return E2EKey{}, err
	}
	return E2EKey{Private: kp.Private, Public: kp.Public}, nil
}

// E2EKeyFromPrivate rebuilds the pair from the private half.
func E2EKeyFromPrivate(priv []byte) (E2EKey, error) {
	if len(priv) != 32 {
		return E2EKey{}, errors.New("e2e key must be 32 bytes")
	}
	kp, err := e2eSuite.GenerateKeypair(bytes.NewReader(priv))
	if err != nil {
		return E2EKey{}, err
	}
	return E2EKey{Private: kp.Private, Public: kp.Public}, nil
}

// EncodeE2EPublic and ParseE2EPublic convert a public key to and from the
// base64url text used in links.
func EncodeE2EPublic(pub []byte) string { return base64.RawURLEncoding.EncodeToString(pub) }

func ParseE2EPublic(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("invalid exit public key")
	}
	return b, nil
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, msg []byte) error {
	if len(msg) > e2eMaxFrame {
		return errors.New("e2e frame too large")
	}
	buf := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	_, err := w.Write(append(buf, msg...))
	return err
}

// ReadFrame reads one length-prefixed frame into buf (which must hold
// e2eMaxFrame bytes) and returns it.
func ReadFrame(r io.Reader, buf []byte) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// SkipFrame discards one frame (a relay that handles a stream itself drops
// the client's handshake meant for the exit).
func SkipFrame(r io.Reader) error {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint16(l[:])))
	return err
}

// E2EInitiator is the client half of a handshake in progress.
type E2EInitiator struct {
	hs *noise.HandshakeState
}

// NewE2EInitiator starts a handshake with the exit whose public key is pub.
// The returned frame carries the auth header for userKey and req; it is
// sent as is after the stream header.
func NewE2EInitiator(pub []byte, userKey Key, req Request) (*E2EInitiator, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: e2eSuite, Random: rand.Reader, Pattern: noise.HandshakeNK,
		Initiator: true, Prologue: e2ePrologue, PeerStatic: pub,
	})
	if err != nil {
		return nil, nil, err
	}
	payload := BuildAuth(userKey, time.Now())
	var rb bytes.Buffer
	if err := WriteRequest(&rb, req); err != nil {
		return nil, nil, err
	}
	payload = append(payload, rb.Bytes()...)
	msg, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, err
	}
	var frame bytes.Buffer
	WriteFrame(&frame, msg)
	return &E2EInitiator{hs: hs}, frame.Bytes(), nil
}

// Finish reads the exit's answer from conn. On StatusOK it returns the
// encrypted connection; otherwise a StatusError.
func (i *E2EInitiator) Finish(conn net.Conn) (net.Conn, error) {
	buf := make([]byte, e2eMaxFrame)
	frame, err := ReadFrame(conn, buf)
	if err != nil {
		return nil, err
	}
	payload, send, recv, err := i.hs.ReadMessage(nil, frame)
	if err != nil {
		return nil, fmt.Errorf("e2e handshake: %w", err)
	}
	if len(payload) == 0 {
		return nil, errors.New("e2e handshake: empty answer")
	}
	if payload[0] != StatusOK {
		return nil, StatusError(payload[0])
	}
	return newE2EConn(conn, send, recv), nil
}

// E2EResponder is the exit half of a handshake in progress.
type E2EResponder struct {
	hs   *noise.HandshakeState
	conn net.Conn
	// User and Request are what the client sent.
	User    *User
	Request Request
}

// AcceptE2E reads the client's first frame from conn and authenticates it
// with auth. The caller then calls Answer with the outcome of the request.
func AcceptE2E(conn net.Conn, key E2EKey, auth *Authenticator) (*E2EResponder, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: e2eSuite, Random: rand.Reader, Pattern: noise.HandshakeNK,
		Initiator: false, Prologue: e2ePrologue,
		StaticKeypair: noise.DHKey{Private: key.Private, Public: key.Public},
	})
	if err != nil {
		return nil, err
	}
	buf := make([]byte, e2eMaxFrame)
	frame, err := ReadFrame(conn, buf)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, frame)
	if err != nil {
		return nil, fmt.Errorf("e2e handshake: %w", err)
	}
	r := bytes.NewReader(payload)
	res, _, err := auth.ReadAuthExt(r)
	if err != nil {
		return nil, fmt.Errorf("e2e auth: %w", err)
	}
	req, err := ReadRequest(r)
	if err != nil {
		return nil, err
	}
	if req.Cmd != CmdTCP && req.Cmd != CmdUDP {
		return nil, fmt.Errorf("e2e: unsupported command %d", req.Cmd)
	}
	return &E2EResponder{hs: hs, conn: conn, User: res.User, Request: req}, nil
}

// Answer completes the handshake with status. On StatusOK it returns the
// encrypted connection.
func (r *E2EResponder) Answer(status byte) (net.Conn, error) {
	payload := make([]byte, 1+mrand.IntN(e2eMaxPadding+1))
	payload[0] = status
	msg, recv, send, err := r.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(r.conn, msg); err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, StatusError(status)
	}
	return newE2EConn(r.conn, send, recv), nil
}

// e2eConn is an encrypted stream.
type e2eConn struct {
	net.Conn
	send, recv *noise.CipherState

	wmu sync.Mutex
	rmu sync.Mutex
	buf []byte // frame buffer
	pt  []byte // decrypted data not yet read
}

func newE2EConn(c net.Conn, send, recv *noise.CipherState) *e2eConn {
	return &e2eConn{Conn: c, send: send, recv: recv, buf: make([]byte, e2eMaxFrame)}
}

func (c *e2eConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), e2eMaxData)
		pad := 0
		if n < e2eSmallData {
			pad = mrand.IntN(e2eMaxPadding + 1)
		}
		pt := make([]byte, 2+n+pad)
		binary.BigEndian.PutUint16(pt, uint16(n))
		copy(pt[2:], p[:n])
		ct, err := c.send.Encrypt(make([]byte, 2, 2+len(pt)+16), nil, pt)
		if err != nil {
			return total, err
		}
		binary.BigEndian.PutUint16(ct, uint16(len(ct)-2))
		if _, err := c.Conn.Write(ct); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *e2eConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pt) == 0 {
		frame, err := ReadFrame(c.Conn, c.buf)
		if err != nil {
			return 0, err
		}
		pt, err := c.recv.Decrypt(frame[:0], nil, frame)
		if err != nil {
			return 0, fmt.Errorf("e2e: %w", err)
		}
		if len(pt) < 2 {
			return 0, errors.New("e2e: short frame")
		}
		n := int(binary.BigEndian.Uint16(pt))
		if 2+n > len(pt) {
			return 0, errors.New("e2e: bad frame")
		}
		c.pt = pt[2 : 2+n]
	}
	n := copy(p, c.pt)
	c.pt = c.pt[n:]
	return n, nil
}

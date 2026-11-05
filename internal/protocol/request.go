package protocol

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/xtaci/smux"
)

const (
	requestVersion = 1

	CmdTCP byte = 1
	CmdUDP byte = 3
	// CmdE2E: the stream carries an end-to-end encrypted session for the
	// exit (frames, see e2e.go); no address follows. A relay forwards it to
	// its upstream; an exit answers StatusE2E and runs the handshake.
	CmdE2E byte = 4
	// CmdFlagE2E marks a TCP or UDP request sent to a relay (CapRelay) by a
	// client that can encrypt for the exit. The client's first e2e frame
	// follows the address. The relay applies its routing to the address:
	// it handles the stream itself (StatusOK, the frame is dropped and data
	// follows in the clear, as for any request) or passes it to the exit
	// (StatusE2E from the exit, then the encrypted session).
	CmdFlagE2E byte = 0x80
)

// Stream status codes sent by the server after it tries to reach the target.
const (
	StatusOK          byte = 0
	StatusFailure     byte = 1
	StatusNotAllowed  byte = 2
	StatusUnreachable byte = 4
	StatusRefused     byte = 5
	// StatusE2E: an end-to-end encrypted session follows (from the exit).
	StatusE2E byte = 6
)

// StatusError is returned by the client when the server could not connect.
type StatusError byte

func (e StatusError) Error() string {
	switch byte(e) {
	case StatusNotAllowed:
		return "server: destination not allowed"
	case StatusUnreachable:
		return "server: host unreachable"
	case StatusRefused:
		return "server: connection refused"
	default:
		return fmt.Sprintf("server: connect failed (status %d)", byte(e))
	}
}

// Request is the header a client sends at the start of every stream.
type Request struct {
	Cmd  byte
	Dest netx.Destination
}

// WriteRequest encodes ver | cmd | atyp | addr | port.
func WriteRequest(w io.Writer, req Request) error {
	buf, err := netx.AppendAddr([]byte{requestVersion, req.Cmd}, req.Dest)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// E2ERequestHeader is the stream header of an end-to-end encrypted request
// sent through a relay: CmdE2E alone when the destination is hidden from
// the relay, otherwise req marked with CmdFlagE2E. The client's first e2e
// frame follows it.
func E2ERequestHeader(req Request, hide bool) ([]byte, error) {
	if hide {
		return []byte{requestVersion, CmdE2E}, nil
	}
	return netx.AppendAddr([]byte{requestVersion, req.Cmd | CmdFlagE2E}, req.Dest)
}

// ReadRequest decodes a stream header.
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return req, err
	}
	if hdr[0] != requestVersion {
		return req, fmt.Errorf("unsupported request version %d", hdr[0])
	}
	req.Cmd = hdr[1]
	if req.Cmd == CmdE2E {
		return req, nil
	}
	network := "tcp"
	if req.Cmd&^CmdFlagE2E == CmdUDP {
		network = "udp"
	}
	d, err := netx.ReadAddr(r, network)
	if err != nil {
		return req, err
	}
	req.Dest = d
	return req, nil
}

// MaxPacketSize is the largest UDP payload carried over a UDP stream.
const MaxPacketSize = 65535

var errPacketTooLarge = errors.New("packet too large")

// AppendPacket encodes one datagram on a UDP stream:
//
//	atyp | addr | port | length(2 BE) | payload
//
// The address is the destination (client→server) or the source (server→client).
func AppendPacket(b []byte, addr netx.Destination, p []byte) ([]byte, error) {
	if len(p) > MaxPacketSize {
		return nil, errPacketTooLarge
	}
	b, err := netx.AppendAddr(b, addr)
	if err != nil {
		return nil, err
	}
	b = append(b, byte(len(p)>>8), byte(len(p)))
	return append(b, p...), nil
}

// ReadPacket decodes one datagram into buf.
func ReadPacket(r io.Reader, buf []byte) (int, netx.Destination, error) {
	addr, err := netx.ReadAddr(r, "udp")
	if err != nil {
		return 0, addr, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return 0, addr, err
	}
	n := int(l[0])<<8 | int(l[1])
	if n > len(buf) {
		return 0, addr, errPacketTooLarge
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, addr, err
	}
	return n, addr, nil
}

// MuxConfig is the smux configuration shared by both ends.
func MuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	// smux's keepalive fires every N seconds exactly, a heartbeat a DPI can
	// spot on a long-lived connection. KeepAlive (keepalive.go) sends the
	// same frames at random intervals instead.
	c.KeepAliveDisabled = true
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 60 * time.Second
	// Leave room for the 8-byte smux header inside one record.
	c.MaxFrameSize = MaxRecordPayload - 64
	// Large per-stream windows keep throughput up on high-latency links.
	c.MaxReceiveBuffer = 16 * 1024 * 1024
	c.MaxStreamBuffer = 4 * 1024 * 1024
	return c
}

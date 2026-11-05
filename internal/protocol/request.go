package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/ddday9/cypher/internal/netx"
	"github.com/xtaci/smux"
)

const (
	requestVersion = 1

	CmdTCP byte = 1

	atypIPv4   byte = 1
	atypDomain byte = 3
	atypIPv6   byte = 4
)

// Stream status codes sent by the server after it tries to reach the target.
const (
	StatusOK          byte = 0
	StatusFailure     byte = 1
	StatusNotAllowed  byte = 2
	StatusUnreachable byte = 4
	StatusRefused     byte = 5
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
	buf := []byte{requestVersion, req.Cmd}
	if a, ok := req.Dest.Addr(); ok {
		if a.Is4() {
			b := a.As4()
			buf = append(append(buf, atypIPv4), b[:]...)
		} else {
			b := a.As16()
			buf = append(append(buf, atypIPv6), b[:]...)
		}
	} else {
		if len(req.Dest.Host) > 255 {
			return errors.New("domain name too long")
		}
		buf = append(buf, atypDomain, byte(len(req.Dest.Host)))
		buf = append(buf, req.Dest.Host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, req.Dest.Port)
	_, err := w.Write(buf)
	return err
}

// ReadRequest decodes a stream header.
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return req, err
	}
	if hdr[0] != requestVersion {
		return req, fmt.Errorf("unsupported request version %d", hdr[0])
	}
	req.Cmd = hdr[1]
	switch hdr[2] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return req, err
		}
		req.Dest.Host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return req, err
		}
		req.Dest.Host = netip.AddrFrom16(b).Unmap().String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return req, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return req, err
		}
		req.Dest.Host = netx.NormalizeHost(string(b))
	default:
		return req, fmt.Errorf("unknown address type %d", hdr[2])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return req, err
	}
	req.Dest.Port = binary.BigEndian.Uint16(p[:])
	req.Dest.Network = "tcp"
	return req, nil
}

// MuxConfig is the smux configuration shared by both ends.
func MuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 15 * time.Second
	c.KeepAliveTimeout = 60 * time.Second
	// Leave room for the 8-byte smux header inside one record.
	c.MaxFrameSize = MaxRecordPayload - 64
	// Large per-stream windows keep throughput up on high-latency links.
	c.MaxReceiveBuffer = 16 * 1024 * 1024
	c.MaxStreamBuffer = 4 * 1024 * 1024
	return c
}

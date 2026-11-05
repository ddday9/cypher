package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/ddday9/cypher/internal/client"
	"github.com/ddday9/cypher/internal/netx"
	"github.com/ddday9/cypher/internal/protocol"
)

const (
	socksVersion = 5

	socksCmdConnect = 1

	socksAtypIPv4   = 1
	socksAtypDomain = 3
	socksAtypIPv6   = 4

	socksRepSuccess         = 0
	socksRepFailure         = 1
	socksRepNotAllowed      = 2
	socksRepHostUnreachable = 4
	socksRepRefused         = 5
	socksRepCmdUnsupported  = 7
	socksRepAtypUnsupported = 8
)

func (in *Inbound) handleSOCKS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != socksVersion {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		conn.Write([]byte{socksVersion, 0xff})
		return
	}
	if _, err := conn.Write([]byte{socksVersion, 0}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != socksVersion {
		return
	}
	var host string
	switch req[3] {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(b).String()
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case socksAtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(conn, socksRepAtypUnsupported)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(conn, pb[:]); err != nil {
		return
	}
	if req[1] != socksCmdConnect {
		// UDP ASSOCIATE and BIND are not supported yet.
		socksReply(conn, socksRepCmdUnsupported)
		return
	}
	dest, err := netx.ParseDestination("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))))
	if err != nil {
		socksReply(conn, socksRepFailure)
		return
	}

	target, err := in.dial(ctx, dest)
	if err != nil {
		socksReply(conn, socksErrorCode(err))
		return
	}
	if err := socksReply(conn, socksRepSuccess); err != nil {
		target.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	netx.Relay(conn, target)
}

func socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVersion, rep, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func socksErrorCode(err error) byte {
	var se protocol.StatusError
	switch {
	case errors.Is(err, client.ErrBlocked):
		return socksRepNotAllowed
	case errors.As(err, &se):
		switch byte(se) {
		case protocol.StatusNotAllowed:
			return socksRepNotAllowed
		case protocol.StatusUnreachable:
			return socksRepHostUnreachable
		case protocol.StatusRefused:
			return socksRepRefused
		}
	case errors.Is(err, syscall.ECONNREFUSED):
		return socksRepRefused
	}
	return socksRepFailure
}

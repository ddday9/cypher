package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

const (
	recordHeaderSize = 4
	// MaxRecordPayload keeps header+data+padding within one TLS record (16 KiB).
	MaxRecordPayload = 16384 - recordHeaderSize

	// The first records of a connection are where traffic classifiers look,
	// so they get heavy random padding.
	earlyRecords    = 16
	earlyMaxPadding = 1024
	// Later, only small records (keepalives, ACK-like writes) are padded.
	smallRecord     = 256
	smallMaxPadding = 256
)

var errBadRecord = errors.New("malformed record")

// RecordConn frames traffic into padded records:
//
//	dataLen uint16 | padLen uint16 | data | padding
//
// It runs inside TLS, so the padding is encrypted; its purpose is to change
// the sizes an observer sees on the wire.
type RecordConn struct {
	net.Conn
	r *bufio.Reader

	rmu      sync.Mutex
	leftover []byte
	rbuf     []byte

	wmu     sync.Mutex
	written int
	prefix  []byte // sent together with the first record (client auth header)
}

// NewRecordConn wraps conn. prefix, if non-nil, is written in front of the
// first record so that the auth header never travels as a separate packet.
func NewRecordConn(conn net.Conn, prefix []byte) *RecordConn {
	return &RecordConn{
		Conn:   conn,
		r:      bufio.NewReaderSize(conn, 32*1024),
		rbuf:   make([]byte, MaxRecordPayload),
		prefix: prefix,
	}
}

func (c *RecordConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.leftover) == 0 {
		var hdr [recordHeaderSize]byte
		if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
			return 0, err
		}
		dataLen := int(binary.BigEndian.Uint16(hdr[0:]))
		padLen := int(binary.BigEndian.Uint16(hdr[2:]))
		if dataLen+padLen > MaxRecordPayload {
			return 0, errBadRecord
		}
		if _, err := io.ReadFull(c.r, c.rbuf[:dataLen]); err != nil {
			return 0, err
		}
		if _, err := c.r.Discard(padLen); err != nil {
			return 0, err
		}
		c.leftover = c.rbuf[:dataLen]
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *RecordConn) paddingFor(dataLen int) int {
	room := MaxRecordPayload - dataLen
	var p int
	switch {
	case c.written < earlyRecords:
		p = rand.IntN(earlyMaxPadding + 1)
	case dataLen < smallRecord:
		p = rand.IntN(smallMaxPadding + 1)
	}
	return min(p, room)
}

func (c *RecordConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 || (total == 0 && c.prefix != nil) {
		chunk := p
		if len(chunk) > MaxRecordPayload {
			chunk = chunk[:MaxRecordPayload]
		}
		padLen := c.paddingFor(len(chunk))

		buf := make([]byte, 0, len(c.prefix)+recordHeaderSize+len(chunk)+padLen)
		buf = append(buf, c.prefix...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(chunk)))
		buf = binary.BigEndian.AppendUint16(buf, uint16(padLen))
		buf = append(buf, chunk...)
		buf = append(buf, make([]byte, padLen)...)
		if _, err := c.Conn.Write(buf); err != nil {
			return total, err
		}
		c.prefix = nil
		c.written++
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

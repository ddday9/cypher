package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	recordHeaderSize = 4
	// MaxRecordPayload keeps header+data+padding within one TLS record (16 KiB).
	MaxRecordPayload = 16384 - recordHeaderSize

	// The first records of a connection, and the first frames of every
	// multiplexed stream, are where traffic classifiers look (e.g. the inner
	// TLS handshake of a proxied HTTPS connection). Those writes are "shaped":
	// cut into chunks of random size, each with random padding.
	earlyRecords     = 16
	earlyStreamFrame = 8
	shapedChunkMin   = 200
	shapedChunkMax   = 4096
	shapedMaxPadding = 512

	// Later, only small records (keepalives, ACK-like writes) are padded.
	smallRecord     = 256
	smallMaxPadding = 256

	// smux v2 frame header: ver(1) cmd(1) length(2 LE) sid(4 LE).
	smuxVersion   = 2
	smuxHeaderLen = 8
	smuxCmdSYN    = 0
	smuxCmdFIN    = 1
	smuxCmdPSH    = 2
)

var errBadRecord = errors.New("malformed record")

// controlBit marks a control record in the padLen field. Padding never
// exceeds MaxRecordPayload (< 0x4000), so the top bits are free. Control
// records are only sent to peers that negotiated protocol version 2.
const controlBit = 0x8000

// ControlHandler receives control records. It runs on the reading
// goroutine and must not block.
type ControlHandler func(typ byte, body []byte)

// RecordConn frames traffic into padded records:
//
//	dataLen uint16 | padLen uint16 | data | padding
//
// It runs inside TLS, so the padding is encrypted; its purpose is to change
// the sizes an observer sees on the wire. Record boundaries carry no meaning:
// the reader sees a plain byte stream, so the writer may cut data anywhere.
type RecordConn struct {
	net.Conn
	r *bufio.Reader

	rmu      sync.Mutex
	leftover []byte
	rbuf     []byte

	wmu     sync.Mutex
	written int
	prefix  []byte         // sent together with the first record (client auth header)
	frames  map[uint32]int // data frames written per smux stream

	bytesIn, bytesOut atomic.Int64
	lastRead          atomic.Int64 // unix nanos of the last record received

	onControl atomic.Pointer[ControlHandler]
}

// SetControlHandler installs the handler for control records.
func (c *RecordConn) SetControlHandler(h ControlHandler) { c.onControl.Store(&h) }

// LastRead returns when the last record arrived from the peer.
func (c *RecordConn) LastRead() time.Time { return time.Unix(0, c.lastRead.Load()) }

// readRecord reads one record into c.rbuf and returns its data and whether
// it is a control record.
func (c *RecordConn) readRecord() ([]byte, bool, error) {
	var hdr [recordHeaderSize]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, false, err
	}
	dataLen := int(binary.BigEndian.Uint16(hdr[0:]))
	padField := binary.BigEndian.Uint16(hdr[2:])
	control := padField&controlBit != 0
	padLen := int(padField &^ controlBit)
	if dataLen+padLen > MaxRecordPayload {
		return nil, false, errBadRecord
	}
	if _, err := io.ReadFull(c.r, c.rbuf[:dataLen]); err != nil {
		return nil, false, err
	}
	if _, err := c.r.Discard(padLen); err != nil {
		return nil, false, err
	}
	c.lastRead.Store(time.Now().UnixNano())
	return c.rbuf[:dataLen], control, nil
}

// WriteControl sends a control record (protocol version 2 peers only).
func (c *RecordConn) WriteControl(typ byte, body []byte) error {
	if 1+len(body) > MaxRecordPayload-64 {
		return errBadRecord
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	padLen := rand.IntN(65)
	buf := make([]byte, 0, len(c.prefix)+recordHeaderSize+1+len(body)+padLen)
	buf = append(buf, c.prefix...) // the auth header, if nothing was sent yet
	c.prefix = nil
	buf = binary.BigEndian.AppendUint16(buf, uint16(1+len(body)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(padLen)|controlBit)
	buf = append(buf, typ)
	buf = append(buf, body...)
	buf = append(buf, make([]byte, padLen)...)
	_, err := c.Conn.Write(buf)
	c.written++
	return err
}

// NewRecordConn wraps conn. prefix, if non-nil, is written in front of the
// first record so that the auth header never travels as a separate packet.
func NewRecordConn(conn net.Conn, prefix []byte) *RecordConn {
	return &RecordConn{
		Conn:   conn,
		r:      bufio.NewReaderSize(conn, 32*1024),
		rbuf:   make([]byte, MaxRecordPayload),
		prefix: prefix,
		frames: make(map[uint32]int),
	}
}

// Traffic returns the payload bytes read and written so far.
func (c *RecordConn) Traffic() (in, out int64) {
	return c.bytesIn.Load(), c.bytesOut.Load()
}

func (c *RecordConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.leftover) == 0 {
		data, control, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		if control {
			if h := c.onControl.Load(); h != nil && len(data) > 0 {
				(*h)(data[0], append([]byte(nil), data[1:]...))
			}
			continue
		}
		c.leftover = data
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	c.bytesIn.Add(int64(n))
	return n, nil
}

// shaped reports whether this write should be cut and padded. smux writes
// exactly one frame per Write, so the frame header is at the start of p.
func (c *RecordConn) shaped(p []byte) bool {
	early := c.written < earlyRecords
	if len(p) < smuxHeaderLen || p[0] != smuxVersion {
		return early
	}
	sid := binary.LittleEndian.Uint32(p[4:])
	switch p[1] {
	case smuxCmdFIN:
		delete(c.frames, sid)
	case smuxCmdPSH:
		// Streams are tracked from their first data frame, so this works on
		// the server too, which never writes SYN. Entries live until FIN.
		if n := c.frames[sid]; n < earlyStreamFrame {
			c.frames[sid] = n + 1
			return true
		}
	}
	return early
}

func randBetween(lo, hi int) int { return lo + rand.IntN(hi-lo+1) }

func (c *RecordConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	shaped := c.shaped(p)
	total := 0
	for len(p) > 0 || (total == 0 && c.prefix != nil) {
		var chunkLen, padLen int
		if shaped {
			chunkLen = min(len(p), randBetween(shapedChunkMin, shapedChunkMax))
			padLen = rand.IntN(shapedMaxPadding + 1)
		} else {
			chunkLen = min(len(p), MaxRecordPayload)
			if chunkLen < smallRecord {
				padLen = rand.IntN(smallMaxPadding + 1)
			}
		}
		padLen = min(padLen, MaxRecordPayload-chunkLen)
		chunk := p[:chunkLen]

		buf := make([]byte, 0, len(c.prefix)+recordHeaderSize+chunkLen+padLen)
		buf = append(buf, c.prefix...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(chunkLen))
		buf = binary.BigEndian.AppendUint16(buf, uint16(padLen))
		buf = append(buf, chunk...)
		buf = append(buf, make([]byte, padLen)...)
		if _, err := c.Conn.Write(buf); err != nil {
			return total, err
		}
		c.prefix = nil
		c.written++
		total += chunkLen
		c.bytesOut.Add(int64(chunkLen))
		p = p[chunkLen:]
	}
	return total, nil
}

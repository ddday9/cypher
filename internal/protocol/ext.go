package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Protocol version 2 is negotiated without changing what version 1 peers
// see: the client puts an extension inside the auth padding (which a v1
// server reads and discards), and a v2 server answers with a control record
// (which it only ever sends to clients that sent the extension).
//
//	ext = magic "CY2\x01" | flags uint16 | session [16] | seq uint32 | mac [16]
//	mac = HMAC-SHA256(key, "cypher/v2/ext" | auth nonce | ext[:26])[:16]

const (
	extSize  = 4 + 2 + 16 + 4 + 16
	extMagic = "CY2\x01"
)

// Extension flags sent by the client.
const (
	// FlagV2: the client understands control records (HELLO, PING/PONG).
	FlagV2 uint16 = 1 << 0
	// FlagSegmented: this connection carries a resumable session (see
	// session.go) instead of a plain smux byte stream.
	FlagSegmented uint16 = 1 << 1
	// FlagAttach: the connection joins the existing session Ext.Session.
	FlagAttach uint16 = 1 << 2
	// FlagQuietIdle: the client does not time out a session that is silent
	// while it has no streams, so the server need not send keepalives then
	// (older clients close a session after 60 s without data).
	FlagQuietIdle uint16 = 1 << 3
)

// Server capabilities announced in HELLO.
const (
	CapPing      uint16 = 1 << 0
	CapSegmented uint16 = 1 << 1
	// CapRelay: the server is a relay with an upstream exit; it accepts
	// requests marked CmdFlagE2E and applies its routing to them.
	CapRelay uint16 = 1 << 2
	// CapQuietIdle: like FlagQuietIdle, from the server's side.
	CapQuietIdle uint16 = 1 << 3
	// CapE2E: the server is an exit that accepts end-to-end encrypted
	// streams (CmdE2E), directly or from a relay.
	CapE2E uint16 = 1 << 4
)

// Ext is the client's protocol extension.
type Ext struct {
	Flags   uint16
	Session [16]byte
	Seq     uint32
}

var extLabel = []byte("cypher/v2/ext")

func extMAC(key Key, nonce, body []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write(extLabel)
	m.Write(nonce)
	m.Write(body)
	return m.Sum(nil)[:16]
}

func (e *Ext) encode(dst []byte, key Key, nonce []byte) {
	copy(dst, extMagic)
	binary.BigEndian.PutUint16(dst[4:], e.Flags)
	copy(dst[6:], e.Session[:])
	binary.BigEndian.PutUint32(dst[22:], e.Seq)
	copy(dst[26:], extMAC(key, nonce, dst[:26]))
}

func parseExt(pad []byte, key Key, nonce []byte) *Ext {
	if len(pad) < extSize || string(pad[:4]) != extMagic {
		return nil
	}
	if !hmac.Equal(pad[26:extSize], extMAC(key, nonce, pad[:26])) {
		return nil
	}
	e := &Ext{Flags: binary.BigEndian.Uint16(pad[4:]), Seq: binary.BigEndian.Uint32(pad[22:])}
	copy(e.Session[:], pad[6:22])
	return e
}

// Control record types (records with the control bit set, see record.go).
const (
	CtlHello byte = 1 // server → client: version(1) caps(2)
	CtlPing  byte = 2 // id(4)
	CtlPong  byte = 3 // id(4)
	CtlData  byte = 4 // session data: offset(8) more(1) payload
	CtlAck   byte = 5 // session ack: offset(8)
	CtlDrain byte = 6 // session: sender will not use this connection any more
)

// Hello is the body of CtlHello.
func Hello(caps uint16) []byte {
	return []byte{2, byte(caps >> 8), byte(caps)}
}

// ParseHello returns the capabilities in a CtlHello body.
func ParseHello(b []byte) (uint16, bool) {
	if len(b) < 3 || b[0] < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b[1:]), true
}

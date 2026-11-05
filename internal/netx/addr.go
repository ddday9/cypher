package netx

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// Address encoding shared by the cypher protocol and SOCKS5:
//
//	atyp(1) | addr (4 bytes IPv4, 16 bytes IPv6, or len(1)+domain) | port(2 BE)
const (
	AtypIPv4   byte = 1
	AtypDomain byte = 3
	AtypIPv6   byte = 4
)

var errAddr = errors.New("invalid address")

// AppendAddr appends the encoded address of d.
func AppendAddr(b []byte, d Destination) ([]byte, error) {
	if a, ok := d.Addr(); ok {
		if a.Is4() {
			v := a.As4()
			b = append(append(b, AtypIPv4), v[:]...)
		} else {
			v := a.As16()
			b = append(append(b, AtypIPv6), v[:]...)
		}
	} else {
		if len(d.Host) == 0 || len(d.Host) > 255 {
			return nil, errAddr
		}
		b = append(b, AtypDomain, byte(len(d.Host)))
		b = append(b, d.Host...)
	}
	return binary.BigEndian.AppendUint16(b, d.Port), nil
}

// ReadAddr decodes an address from r.
func ReadAddr(r io.Reader, network string) (Destination, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Destination{}, err
	}
	d := Destination{Network: network}
	switch t[0] {
	case AtypIPv4:
		var v [4]byte
		if _, err := io.ReadFull(r, v[:]); err != nil {
			return d, err
		}
		d.Host = netip.AddrFrom4(v).String()
	case AtypIPv6:
		var v [16]byte
		if _, err := io.ReadFull(r, v[:]); err != nil {
			return d, err
		}
		d.Host = netip.AddrFrom16(v).Unmap().String()
	case AtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return d, err
		}
		v := make([]byte, l[0])
		if _, err := io.ReadFull(r, v); err != nil {
			return d, err
		}
		if len(v) == 0 {
			return d, errAddr
		}
		d.Host = NormalizeHost(string(v))
	default:
		return d, errAddr
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return d, err
	}
	d.Port = binary.BigEndian.Uint16(p[:])
	return d, nil
}

// ParseAddr decodes an address at the start of b and returns its length.
func ParseAddr(b []byte, network string) (Destination, int, error) {
	r := &countReader{b: b}
	d, err := ReadAddr(r, network)
	if err != nil {
		return d, 0, errAddr
	}
	return d, r.n, nil
}

type countReader struct {
	b []byte
	n int
}

func (r *countReader) Read(p []byte) (int, error) {
	if r.n >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.n:])
	r.n += n
	return n, nil
}

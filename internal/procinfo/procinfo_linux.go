package procinfo

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// lookup finds the socket inode in /proc/net/{tcp,udp}{,6}, then the process
// holding that inode among /proc/<pid>/fd.
func lookup(network string, addr netip.AddrPort) (string, error) {
	inode, err := findInode(network, addr)
	if err != nil {
		return "", err
	}
	target := fmt.Sprintf("socket:[%d]", inode)
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(p + "/fd/" + fd.Name()); err == nil && l == target {
				exe, err := os.Readlink(p + "/exe")
				if err != nil {
					return "", err
				}
				return exe, nil
			}
		}
	}
	return "", ErrNotFound
}

func findInode(network string, addr netip.AddrPort) (uint64, error) {
	files := []string{"/proc/net/" + network, "/proc/net/" + network + "6"}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			local, ok := parseProcAddr(fields[1])
			if !ok || local.Port() != addr.Port() {
				continue
			}
			la := local.Addr().Unmap()
			if !la.IsUnspecified() && la != addr.Addr() {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err == nil && inode != 0 {
				fh.Close()
				return inode, nil
			}
		}
		fh.Close()
	}
	return 0, ErrNotFound
}

// parseProcAddr decodes "0100007F:1F90" (IPv4) or the 32-hex-digit IPv6
// form; addresses are stored as host-endian 32-bit words.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i < len(raw); i += 4 {
		w := binary.LittleEndian.Uint32(raw[i:])
		binary.BigEndian.PutUint32(raw[i:], w)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	a, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(a, uint16(port)), true
}

func list() ([]Process, error) {
	procs, _ := filepath.Glob("/proc/[0-9]*")
	var out []Process
	for _, p := range procs {
		exe, err := os.Readlink(p + "/exe")
		if err != nil {
			continue
		}
		out = append(out, Process{Name: filepath.Base(exe), Path: exe})
	}
	return out, nil
}

package procinfo

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

// table fetches an extended TCP/UDP table for one address family.
func table(proc *windows.LazyProc, family uint32, class uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), uintptr(class), 0)
		switch r {
		case 0:
			return buf[:size], nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			continue
		default:
			return nil, windows.Errno(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

func port(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) } // network order in the low 16 bits

// findPID walks MIB_{TCP,UDP}{,6}ROW_OWNER_PID rows looking for addr.
func findPID(network string, addr netip.AddrPort) (uint32, error) {
	type layout struct {
		family          uint32
		rowSize         int
		addrOff, addrLn int
		portOff, pidOff int
	}
	var layouts []layout
	proc, class := getExtendedTcpTable, uint32(tcpTableOwnerPidAll)
	if network == "udp" {
		proc, class = getExtendedUdpTable, uint32(udpTableOwnerPid)
		layouts = []layout{
			{windows.AF_INET, 12, 0, 4, 4, 8},     // MIB_UDPROW_OWNER_PID
			{windows.AF_INET6, 28, 0, 16, 20, 24}, // MIB_UDP6ROW_OWNER_PID
		}
	} else {
		layouts = []layout{
			{windows.AF_INET, 24, 4, 4, 8, 20},    // MIB_TCPROW_OWNER_PID
			{windows.AF_INET6, 56, 0, 16, 20, 52}, // MIB_TCP6ROW_OWNER_PID
		}
	}
	for _, l := range layouts {
		buf, err := table(proc, l.family, class)
		if err != nil || len(buf) < 4 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(buf))
		rows := buf[4:] // rows follow the DWORD count
		for i := 0; i < n && (i+1)*l.rowSize <= len(rows); i++ {
			row := rows[i*l.rowSize : (i+1)*l.rowSize]
			if port(row[l.portOff:]) != addr.Port() {
				continue
			}
			a, _ := netip.AddrFromSlice(row[l.addrOff : l.addrOff+l.addrLn])
			a = a.Unmap()
			if !a.IsUnspecified() && a != addr.Addr() {
				continue
			}
			return binary.LittleEndian.Uint32(row[l.pidOff:]), nil
		}
	}
	return 0, ErrNotFound
}

func exePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func lookup(network string, addr netip.AddrPort) (string, error) {
	pid, err := findPID(network, addr)
	if err != nil {
		return "", err
	}
	return exePath(pid)
}

func list() ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Process
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out = append(out, Process{Name: windows.UTF16ToString(e.ExeFile[:])})
	}
	return out, nil
}

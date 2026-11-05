package procinfo

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
)

// TestLookupSelf opens sockets in this test process and checks that they
// are attributed to the test binary.
func TestLookupSelf(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("not supported")
	}
	self, _ := os.Executable()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	path, err := Lookup("tcp", local)
	if err != nil || Name(path) != Name(self) {
		t.Fatalf("tcp: got %q %v, want %q", path, err, self)
	}
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	path, err = Lookup("udp", netip.MustParseAddrPort(u.LocalAddr().String()))
	if err != nil || Name(path) != Name(self) {
		t.Fatalf("udp: got %q %v", path, err)
	}
	if _, err := Lookup("tcp", netip.MustParseAddrPort("127.0.0.1:1")); err == nil {
		t.Fatal("found an owner for an unused port")
	}
	ps, err := List()
	if err != nil || len(ps) == 0 {
		t.Fatalf("list: %v %d", err, len(ps))
	}
	if Name(`C:\Games\Dota 2\game\bin\win64\Dota2.EXE`) != "dota2.exe" {
		t.Fatal("Name does not handle Windows paths")
	}
}

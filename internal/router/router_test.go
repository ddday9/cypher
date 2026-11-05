package router

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
	"google.golang.org/protobuf/encoding/protowire"
)

func msg(fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = append(b, f...)
	}
	return b
}

func fBytes(num protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func fVarint(num protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func domain(typ int, value string, attrs ...string) []byte {
	m := msg(fVarint(1, uint64(typ)), fBytes(2, []byte(value)))
	for _, a := range attrs {
		m = append(m, fBytes(3, msg(fBytes(1, []byte(a)), fVarint(2, 1)))...)
	}
	return m
}

func cidr(s string) []byte {
	p := netip.MustParsePrefix(s)
	return msg(fBytes(1, p.Addr().AsSlice()), fVarint(2, uint64(p.Bits())))
}

// writeGeo writes small geosite/geoip files in the Xray format.
func writeGeo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	site := msg(
		fBytes(1, msg(fBytes(1, []byte("GOOGLE")),
			fBytes(2, domain(domainSuffix, "google.com")),
			fBytes(2, domain(domainFull, "www.youtube.com", "ads")),
			fBytes(2, domain(domainPlain, "googlevideo")),
			fBytes(2, domain(domainRegex, `^gstatic\d+\.net$`)),
		)),
		fBytes(1, msg(fBytes(1, []byte("CATEGORY-RU")),
			fBytes(2, domain(domainSuffix, "yandex.ru")),
			fBytes(2, domain(domainSuffix, "vk.com")),
		)),
	)
	ip := msg(
		fBytes(1, msg(fBytes(1, []byte("RU")), fBytes(2, cidr("5.8.0.0/16")), fBytes(2, cidr("77.88.0.0/18")), fBytes(2, cidr("2a02:6b8::/32")))),
		fBytes(1, msg(fBytes(1, []byte("PRIVATE")), fBytes(2, cidr("10.0.0.0/8")), fBytes(2, cidr("192.168.0.0/16")), fBytes(2, cidr("127.0.0.0/8")))),
	)
	sp, ipp := filepath.Join(dir, "geosite.dat"), filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(sp, site, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipp, ip, 0o644); err != nil {
		t.Fatal(err)
	}
	return sp, ipp
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f[host], nil
}

func dest(host string, port uint16) netx.Destination {
	return netx.Destination{Network: "tcp", Host: host, Port: port}
}

func TestRouting(t *testing.T) {
	sp, ipp := writeGeo(t)
	cfg := config.RoutingConfig{
		DomainStrategy: "IPIfNonMatch",
		Rules: []config.RuleConfig{
			{Domain: []string{"geosite:google@ads"}, Outbound: "block"},
			{Domain: []string{"geosite:category-ru", "full:example.org", "regexp:^test\\d+\\.local$"}, Outbound: "direct"},
			{IP: []string{"geoip:private", "geoip:ru", "1.2.3.4"}, Outbound: "direct"},
			{Domain: []string{"geosite:google"}, Port: "443,8000-9000", Outbound: "proxy"},
			{Port: "25", Outbound: "block"},
		},
	}
	r, err := New(cfg, "proxy", NewGeoLoader(sp, ipp))
	if err != nil {
		t.Fatal(err)
	}
	r.resolver = fakeResolver{
		"ru-hosted.com": {netip.MustParseAddr("5.8.1.1")},
		"other.com":     {netip.MustParseAddr("8.8.8.8")},
	}
	r.defaultTag = "default"

	cases := []struct {
		d    netx.Destination
		want string
	}{
		{dest("www.youtube.com", 443), "block"}, // geosite attribute filter
		{dest("yandex.ru", 443), "direct"},
		{dest("music.yandex.ru", 443), "direct"}, // suffix matches subdomains
		{dest("notyandex.ru", 443), "default"},   // ...but not other names
		{dest("example.org", 80), "direct"},
		{dest("www.example.org", 80), "default"}, // full: is exact
		{dest("test42.local", 80), "direct"},
		{dest("192.168.1.10", 80), "direct"},
		{dest("77.88.10.1", 443), "direct"},
		{dest("77.88.64.1", 443), "default"}, // just outside 77.88.0.0/18
		{dest("2a02:6b8::1", 443), "direct"},
		{dest("1.2.3.4", 443), "direct"},
		{dest("mail.google.com", 443), "proxy"},
		{dest("r1.googlevideo.com", 8443), "proxy"},
		{dest("gstatic12.net", 443), "proxy"},
		{dest("google.com", 80), "default"}, // port does not match
		{dest("smtp.example.net", 25), "block"},
		{dest("ru-hosted.com", 443), "direct"}, // IPIfNonMatch
		{dest("other.com", 443), "default"},
	}
	for _, c := range cases {
		if got := r.Route(context.Background(), Metadata{Dest: c.d}); got != c.want {
			t.Errorf("%s: got %q, want %q", c.d, got, c.want)
		}
	}
}

func TestAsIsDoesNotResolve(t *testing.T) {
	sp, ipp := writeGeo(t)
	r, err := New(config.RoutingConfig{Rules: []config.RuleConfig{
		{IP: []string{"geoip:ru"}, Outbound: "direct"},
	}}, "proxy", NewGeoLoader(sp, ipp))
	if err != nil {
		t.Fatal(err)
	}
	r.resolver = fakeResolver{"ru-hosted.com": {netip.MustParseAddr("5.8.1.1")}}
	if got := r.Route(context.Background(), Metadata{Dest: dest("ru-hosted.com", 443)}); got != "proxy" {
		t.Errorf("AsIs resolved the domain: got %q", got)
	}
}

func TestInverseGeoIP(t *testing.T) {
	sp, ipp := writeGeo(t)
	r, err := New(config.RoutingConfig{Rules: []config.RuleConfig{
		{IP: []string{"geoip:!ru"}, Outbound: "proxy"},
	}}, "direct", NewGeoLoader(sp, ipp))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Route(context.Background(), Metadata{Dest: dest("8.8.8.8", 53)}); got != "proxy" {
		t.Errorf("8.8.8.8: got %q", got)
	}
	if got := r.Route(context.Background(), Metadata{Dest: dest("5.8.0.1", 53)}); got != "direct" {
		t.Errorf("5.8.0.1: got %q", got)
	}
}

func TestErrors(t *testing.T) {
	sp, ipp := writeGeo(t)
	geo := NewGeoLoader(sp, ipp)
	bad := []config.RuleConfig{
		{Domain: []string{"geosite:nonexistent"}, Outbound: "x"},
		{IP: []string{"geoip:zz"}, Outbound: "x"},
		{IP: []string{"300.1.1.1"}, Outbound: "x"},
		{Port: "70000", Outbound: "x"},
		{Domain: []string{"regexp:("}, Outbound: "x"},
		{Outbound: "x"},
		{Domain: []string{"a.com"}},
	}
	for _, rc := range bad {
		if _, err := New(config.RoutingConfig{Rules: []config.RuleConfig{rc}}, "d", geo); err == nil {
			t.Errorf("expected error for %+v", rc)
		}
	}
}

func TestIPSetMerge(t *testing.T) {
	s := newIPSet([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.0.128/25"),
		netip.MustParsePrefix("::/0"),
	})
	if len(s.ranges) != 2 {
		t.Fatalf("ranges not merged: %v", s.ranges)
	}
	for _, a := range []string{"10.0.0.0", "10.0.1.255", "::1", "2001:db8::1"} {
		if !s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s should match", a)
		}
	}
	for _, a := range []string{"10.0.2.0", "9.255.255.255"} {
		if s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s should not match", a)
		}
	}
}

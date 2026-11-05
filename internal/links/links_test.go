package links

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ddday9/cypher/internal/protocol"
)

func TestRoundTrip(t *testing.T) {
	l := Link{Name: "Нидерланды #1", Server: "nl.example.com:8443", Key: protocol.GenerateKey().String(),
		ServerName: "cdn.example.com", Fingerprint: "chrome", Connections: 3, AntiFreeze: "on", Single: true}
	got, err := Parse(Format(l))
	if err != nil || got != l {
		t.Fatalf("got %+v err %v\nlink %s", got, err, Format(l))
	}
	// Defaults: port 443, name = host.
	k := protocol.GenerateKey().String()
	got, err = Parse("cypher://" + k + "@example.com")
	if err != nil || got.Server != "example.com:443" || got.Name != "example.com" {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	if _, err := Parse("vless://x@y:1"); err == nil {
		t.Fatal("foreign scheme accepted")
	}
	if _, err := Parse("cypher://short@y:1"); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestParseList(t *testing.T) {
	a := Format(Link{Name: "a", Server: "a.example:443", Key: protocol.GenerateKey().String()})
	b := Format(Link{Name: "b", Server: "b.example:443", Key: protocol.GenerateKey().String()})
	plain := a + "\n# comment\nvless://ignored\n" + b + "\n"
	for _, text := range []string{plain, base64.StdEncoding.EncodeToString([]byte(plain))} {
		got, errs := ParseList(text)
		if len(got) != 2 || len(errs) != 0 || got[0].Name != "a" || got[1].Name != "b" {
			t.Fatalf("got %+v errs %v for %q", got, errs, strings.TrimSpace(text)[:20])
		}
	}
}

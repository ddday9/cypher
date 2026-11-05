package client

import (
	"testing"
	"time"
)

func TestDialLimiter(t *testing.T) {
	l := &dialLimiter{n: 3, window: 300 * time.Millisecond}
	start := time.Now()
	for range 3 {
		l.wait(func() bool { return false })
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("burst within the limit was delayed")
	}
	l.wait(func() bool { return false }) // the 4th must wait for the window
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("4th dial allowed after %v, want about 300ms", d)
	}
}

func TestParseAntiFreeze(t *testing.T) {
	for in, want := range map[string]string{"": "auto", "AUTO": "auto", "on": "on", "always": "on", "off": "off"} {
		if got, err := parseAntiFreeze(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := parseAntiFreeze("sometimes"); err == nil {
		t.Error("bad value accepted")
	}
}

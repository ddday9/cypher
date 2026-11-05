package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadAndRun(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		w.Write([]byte("data-" + r.URL.Path))
	}))
	defer srv.Close()
	dir := t.TempDir()
	srcs := []Source{{URL: srv.URL + "/site", Path: filepath.Join(dir, "geosite.dat")}, {URL: srv.URL + "/ip", Path: filepath.Join(dir, "geoip.dat")}}

	if err := EnsureAll(context.Background(), srcs); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(srcs[0].Path); string(b) != "data-/site" {
		t.Fatalf("content %q", b)
	}
	if err := EnsureAll(context.Background(), srcs); err != nil || hits.Load() != 2 {
		t.Fatalf("existing files downloaded again: %d %v", hits.Load(), err)
	}
	if err := Download(context.Background(), srv.URL+"/missing", filepath.Join(dir, "x")); err == nil {
		t.Fatal("404 accepted")
	}
	// Age the files: Run must refresh them right away.
	old := time.Now().Add(-48 * time.Hour)
	for _, s := range srcs {
		os.Chtimes(s.Path, old, old)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, srcs, 24*time.Hour); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for hits.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if hits.Load() != 4 {
		t.Fatalf("stale files not refreshed: %d", hits.Load())
	}
	for _, in := range []string{"off", "0"} {
		if d, err := ParseInterval(in); err != nil || d != 0 {
			t.Fatalf("%s: %v %v", in, d, err)
		}
	}
	if _, err := ParseInterval("5m"); err == nil {
		t.Fatal("too short interval accepted")
	}
}

package protocol

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/ddday9/cypher/internal/netx"
)

func TestE2E(t *testing.T) {
	key, err := GenerateE2EKey()
	if err != nil {
		t.Fatal(err)
	}
	user := User{Name: "alice", Key: GenerateKey()}
	auth := NewAuthenticator([]User{user})
	a, b := net.Pipe()
	req := Request{Cmd: CmdTCP, Dest: netx.Destination{Network: "tcp", Host: "example.com", Port: 443}}

	init, frame, err := NewE2EInitiator(key.Public, user.Key, req)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		c   net.Conn
		err error
	}
	srv := make(chan result, 1)
	go func() {
		r, err := AcceptE2E(b, key, auth)
		if err != nil {
			srv <- result{nil, err}
			return
		}
		if r.User.Name != "alice" || r.Request.Dest != req.Dest {
			t.Errorf("got %s %v", r.User.Name, r.Request.Dest)
		}
		c, err := r.Answer(StatusOK)
		srv <- result{c, err}
	}()
	go a.Write(frame)
	cc, err := init.Finish(a)
	if err != nil {
		t.Fatal(err)
	}
	sr := <-srv
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	big := bytes.Repeat([]byte("0123456789"), 10000) // several frames
	go cc.Write(big)
	got := make([]byte, len(big))
	if _, err := io.ReadFull(sr.c, got); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("client → server: %v", err)
	}
	go sr.c.Write([]byte("pong"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cc, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("server → client: %q %v", buf, err)
	}
}

func TestE2ERejects(t *testing.T) {
	key, _ := GenerateE2EKey()
	other, _ := GenerateE2EKey()
	user := User{Name: "alice", Key: GenerateKey()}
	req := Request{Cmd: CmdTCP, Dest: netx.Destination{Network: "tcp", Host: "1.2.3.4", Port: 80}}
	try := func(pub []byte, k Key) error {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		_, frame, _ := NewE2EInitiator(pub, k, req)
		go a.Write(frame)
		_, err := AcceptE2E(b, key, NewAuthenticator([]User{user}))
		return err
	}
	if err := try(other.Public, user.Key); err == nil {
		t.Error("handshake for another server's key accepted")
	}
	if err := try(key.Public, GenerateKey()); err == nil {
		t.Error("unknown user accepted")
	}
	// Replaying a recorded first frame is rejected (auth nonce cache).
	auth := NewAuthenticator([]User{user})
	_, frame, _ := NewE2EInitiator(key.Public, user.Key, req)
	for i, want := range []bool{true, false} {
		a, b := net.Pipe()
		go a.Write(frame)
		_, err := AcceptE2E(b, key, auth)
		if (err == nil) != want {
			t.Errorf("attempt %d: err = %v", i, err)
		}
		a.Close()
		b.Close()
	}
}

package telehash

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/fd/go-util/log"
	"runtime"
	"testing"
	"time"
)

func init() {
	Log.SetLevel(log.DEBUG)
}

func TestOpen(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		key_a = make_key()
		a     = make_switch("127.0.0.1:4000", key_a)

		key_b = make_key()
		b     = make_switch("127.0.0.1:4001", key_b)
	)

	go a.Run()
	go b.Run()

	defer a.Close()
	defer b.Close()

	hashname, err := a.RegisterPeer("127.0.0.1:4001", &key_b.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = a.Open(hashname)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	for _, l := range a.lines {
		l.send_pkt([]byte("hello world"))
	}

	time.Sleep(1 * time.Second)

	if a.err != nil {
		t.Fatal(a.err)
	}
	if b.err != nil {
		t.Fatal(b.err)
	}
}

func make_key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func make_switch(addr string, key *rsa.PrivateKey) *Switch {
	s, err := NewSwitch(addr, key)
	if err != nil {
		panic(err)
	}
	return s
}

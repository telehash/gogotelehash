package telehash

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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

	greetings := HandlerFunc(func(c *Channel) {
		msg, err := c.Receive(nil)
		if err != nil {
			t.Fatal(err)
		}
		Log.Infof("msg=%q", msg)

		for i := 0; i < 1000; i++ {
			msg, err = c.Receive(nil)
			if err != nil {
				t.Fatal(err)
			}

			Log.Infof("msg=%q", msg)
		}
	})

	var (
		key_a = make_key()
		a     = make_switch("0.0.0.0:4000", key_a, nil)

		key_b = make_key()
		b     = make_switch("0.0.0.0:4001", key_b, greetings)
	)

	a.Start()
	b.Start()
	defer a.Stop()
	defer b.Stop()

	go func() {

		hashname, err := a.RegisterPeer("127.0.0.1:4001", &key_b.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		channel, err := a.Open(hashname, "_greetings")
		if err != nil {
			t.Fatal(err)
		}

		defer channel.Close()

		for i := 0; i < 1000; i++ {
			err := channel.Send(nil, []byte(fmt.Sprintf("hello world (%d)", i)))
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	time.Sleep(1 * time.Second)
}

func TestSeek(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		key_a = make_key()
		a     = make_switch("0.0.0.0:4000", key_a, HandlerFunc(ping_pong))

		key_b = make_key()
		b     = make_switch("0.0.0.0:4001", key_b, HandlerFunc(ping_pong))

		key_c = make_key()
		c     = make_switch("0.0.0.0:4002", key_c, HandlerFunc(ping_pong))
	)

	a.Start()
	b.Start()
	c.Start()
	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	go func() {
		_, err := b.RegisterPeer("127.0.0.1:4000", &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		Log.Infof("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
		time.Sleep(100 * time.Millisecond)
		Log.Infof("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
	}()

	go func() {
		_, err := c.RegisterPeer("127.0.0.1:4000", &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		Log.Infof("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
		time.Sleep(100 * time.Millisecond)
		Log.Infof("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
	}()

	time.Sleep(1 * time.Second)
}

func make_key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func make_switch(addr string, key *rsa.PrivateKey, h Handler) *Switch {
	s, err := NewSwitch(addr, key, h)
	if err != nil {
		panic(err)
	}
	return s
}

func ping_pong(c *Channel) {
	for {
		body, err := c.Receive(nil)
		if err != nil {
			return
		}

		err = c.Send(nil, body)
		if err != nil {
			return
		}
	}
}

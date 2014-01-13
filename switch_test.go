package telehash

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/ipv4"
	"io"
	"runtime"
	"testing"
	"time"
)

func TestOpen(t *testing.T) {
	defer capture_runtime_state().validate(t)

	runtime.GOMAXPROCS(runtime.NumCPU())

	done := make(chan bool, 2)

	greetings := HandlerFunc(func(c *Channel) {
		defer func() { done <- true }()

		buf := make([]byte, 1500)

		n, err := c.Receive(nil, buf)
		if err != nil {
			t.Fatalf("err=%s", err)
		}
		Log.Infof("msg=%q", buf[:n])

		for {
			buf = buf[:cap(buf)]

			n, err = c.Receive(nil, buf)
			if err == io.EOF {
				Log.Infof("err=EOF")
				break
			}
			if err != nil {
				t.Fatal(err)
			}

			buf = buf[:n]

			// Log.Infof("msg=%q", buf)
		}
	})

	var (
		key_a = make_key()
		a     = must_start_switch(make_switch("0.0.0.0:4000", key_a, nil))

		key_b = make_key()
		b     = must_start_switch(make_switch("0.0.0.0:4001", key_b, greetings))
	)

	defer a.Stop()
	defer b.Stop()

	go func() {
		defer func() { done <- true }()

		addr, err := ipv4.ResolveAddr("127.0.0.1:4001")
		if err != nil {
			t.Fatal(err)
		}

		hashname, err := a.Seed("ipv4", addr, &key_b.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		channel, err := a.Open(ChannelOptions{To: hashname, Type: "_greetings"})
		if err != nil {
			t.Fatal(err)
		}

		defer channel.Close()

		for i := 0; i < 100000; i++ {
			_, err := channel.Send(nil, []byte(fmt.Sprintf("hello world (%d)", i)))
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	<-done
	<-done
}

func TestSeek(t *testing.T) {
	defer capture_runtime_state().validate(t)

	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		key_a = make_key()
		a     = must_start_switch(make_switch("0.0.0.0:4000", key_a, HandlerFunc(ping_pong)))

		key_b = make_key()
		b     = must_start_switch(make_switch("0.0.0.0:4001", key_b, HandlerFunc(ping_pong)))

		key_c = make_key()
		c     = must_start_switch(make_switch("0.0.0.0:4002", key_c, HandlerFunc(ping_pong)))
	)

	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	go func() {
		addr, err := ipv4.ResolveAddr("127.0.0.1:4000")
		if err != nil {
			t.Fatal(err)
		}

		_, err = b.Seed("ipv4", addr, &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
		Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
	}()

	go func() {
		addr, err := ipv4.ResolveAddr("127.0.0.1:4000")
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.Seed("ipv4", addr, &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
		Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
	}()

	time.Sleep(60 * time.Second)
}

func TestRelay(t *testing.T) {
	defer capture_runtime_state().validate(t)

	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		key_a = make_key()
		a     = must_start_switch(make_switch("0.0.0.0:4000", key_a, HandlerFunc(ping_pong)))

		key_b = make_key()
		b     = must_start_switch(make_switch("0.0.0.0:4001", key_b, HandlerFunc(ping_pong)))

		key_c = make_key()
		c     = must_start_switch(make_switch("0.0.0.0:4002", key_c, HandlerFunc(ping_pong)))
	)

	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	// b.net.deny_from_net("127.0.0.1:4002")
	// c.net.deny_from_net("127.0.0.1:4001")

	go func() {
		addr, err := ipv4.ResolveAddr("127.0.0.1:4000")
		if err != nil {
			t.Fatal(err)
		}

		_, err = b.Seed("ipv4", addr, &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
		time.Sleep(200 * time.Millisecond)
		Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
	}()

	go func() {
		addr, err := ipv4.ResolveAddr("127.0.0.1:4000")
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.Seed("ipv4", addr, &key_a.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		// Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
		time.Sleep(100 * time.Millisecond)
		Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
	}()

	time.Sleep(60 * time.Second)
}

func make_key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func make_switch(addr string, key *rsa.PrivateKey, h Handler) *Switch {
	return &Switch{
		Key:     key,
		Handler: h,
		Transports: []net.Transport{
			&ipv4.Transport{Addr: addr},
		},
	}
}

func must_start_switch(s *Switch) *Switch {
	err := s.Start()
	if err != nil {
		panic(err)
	}
	return s
}

func ping_pong(c *Channel) {
	var (
		buf = make([]byte, 1500)
	)

	for {
		n, err := c.Receive(nil, buf)
		if err != nil {
			return
		}

		_, err = c.Send(nil, buf[:n])
		if err != nil {
			return
		}
	}
}

type runtime_state struct {
	NumGoroutine int
}

func capture_runtime_state() runtime_state {
	return runtime_state{
		NumGoroutine: runtime.NumGoroutine(),
	}
}

func (a runtime_state) validate(t *testing.T) {
	time.Sleep(1 * time.Millisecond)
	b := capture_runtime_state()
	if a.NumGoroutine != b.NumGoroutine {
		// panic(fmt.Sprintf("NumGoroutine: delta=%d", b.NumGoroutine-a.NumGoroutine))
		t.Logf("NumGoroutine: delta=%d", b.NumGoroutine-a.NumGoroutine)
	}
}

package telehash_test

import (
	"fmt"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/dht/kademlia"
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

	greetings := telehash.HandlerFunc(func(c *telehash.Channel) {
		defer func() { done <- true }()

		buf := make([]byte, 1500)

		n, err := c.Receive(nil, buf)
		if err != nil {
			t.Fatalf("err=%s", err)
		}
		telehash.Log.Infof("msg=%q", buf[:n])

		for {
			buf = buf[:cap(buf)]

			n, err = c.Receive(nil, buf)
			if err == io.EOF {
				telehash.Log.Infof("err=EOF")
				break
			}
			if err != nil {
				t.Fatal(err)
			}

			buf = buf[:n]

			// telehash.Log.Infof("msg=%q", buf)
		}
	})

	var (
		b = must_start_switch(make_switch("0.0.0.0:4001", greetings, nil))
		a = must_start_switch(make_switch("0.0.0.0:4000", nil, b))
	)

	defer a.Stop()
	defer b.Stop()

	go func() {
		defer func() { done <- true }()

		channel, err := a.Seek(b.LocalHashname()).Open(telehash.ChannelOptions{Type: "_greetings"})
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
		a = must_start_switch(make_switch("0.0.0.0:4000", telehash.HandlerFunc(ping_pong), nil))
		b = must_start_switch(make_switch("0.0.0.0:4001", telehash.HandlerFunc(ping_pong), a))
		c = must_start_switch(make_switch("0.0.0.0:4002", telehash.HandlerFunc(ping_pong), a))
	)

	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	go func() {

		peer := b.Seek(a.LocalHashname())
		if peer == nil {
			t.Fatal(telehash.ErrPeerNotFound)
		}

		// telehash.Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
		telehash.Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname()))
	}()

	go func() {

		peer := b.Seek(a.LocalHashname())
		if peer == nil {
			t.Fatal(telehash.ErrPeerNotFound)
		}

		// telehash.Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
		telehash.Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname()))
	}()

	time.Sleep(60 * time.Second)
}

func TestRelay(t *testing.T) {
	defer capture_runtime_state().validate(t)

	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		a = must_start_switch(make_switch("0.0.0.0:4000", telehash.HandlerFunc(ping_pong), nil))
		b = must_start_switch(make_switch("0.0.0.0:4001", telehash.HandlerFunc(ping_pong), a))
		c = must_start_switch(make_switch("0.0.0.0:4002", telehash.HandlerFunc(ping_pong), a))
	)

	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	// b.net.deny_from_net("127.0.0.1:4002")
	// c.net.deny_from_net("127.0.0.1:4001")

	go func() {

		peer := b.Seek(a.LocalHashname())
		if peer == nil {
			t.Fatal(telehash.ErrPeerNotFound)
		}

		// telehash.Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname(), 5))
		time.Sleep(200 * time.Millisecond)
		telehash.Log.Noticef("b: seek=%+v", b.Seek(c.LocalHashname()))
	}()

	go func() {

		peer := b.Seek(a.LocalHashname())
		if peer == nil {
			t.Fatal(telehash.ErrPeerNotFound)
		}

		// telehash.Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname(), 5))
		time.Sleep(100 * time.Millisecond)
		telehash.Log.Noticef("c: seek=%+v", c.Seek(b.LocalHashname()))
	}()

	time.Sleep(60 * time.Second)
}

func make_switch(addr string, h telehash.Handler, seed *telehash.Switch) *telehash.Switch {
	return &telehash.Switch{
		Handler: h,
		Components: []telehash.Component{
			&ipv4.Transport{Addr: addr},
			&kademlia.DHT{Seeds: []*telehash.Identity{seed.Identity()}},
		},
	}
}

func must_start_switch(s *telehash.Switch) *telehash.Switch {
	err := s.Start()
	if err != nil {
		panic(err)
	}
	return s
}

func ping_pong(c *telehash.Channel) {
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

package main

import (
	"fmt"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/dht/kademlia"
	"github.com/telehash/gogotelehash/net/ipv4"
	"github.com/telehash/gogotelehash/net/ipv6"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

import (
	"net/http"
	_ "net/http/pprof"
)

func main() {
	seeds, err := telehash.LoadIdenities(env("SEED_FILE", "seeds.json"))
	assert(err)

	if env("PROFILE", "false") == "true" {
		go func() {
			http.ListenAndServe("localhost:6060", nil)
		}()
	}

	defer fmt.Println("BYE!")

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	port := env("PORT", "4000")

	s := &telehash.Switch{
		Handler: telehash.HandlerFunc(pong),
		Components: []telehash.Component{
			&ipv4.Transport{Addr: ":" + port},
			&ipv6.Transport{Addr: ":" + port},
			&kademlia.DHT{Seeds: seeds},
		},
	}

	assert(s.Start())

	time.Sleep(100 * time.Millisecond)

	defer func() { assert(s.Stop()) }()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	fmt.Println("shutting down...")
}

func pong(c *telehash.Channel) {
	var (
		body = make([]byte, 1500)
	)

	for {
		n, err := c.Receive(nil, body)
		if err != nil {
			return
		}

		_, err = c.Send(nil, body[:n])
		if err != nil {
			return
		}
	}
}

func env(key, def string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return def
}

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

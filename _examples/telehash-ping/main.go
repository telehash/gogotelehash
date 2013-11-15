package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/fd/go-util/log"
	"github.com/telehash/gogotelehash"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	defer fmt.Println("BYE!")

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	telehash.Log.SetLevel(log.DEBUG)

	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}

	s, err := telehash.NewSwitch("0.0.0.0:"+port, make_key(), telehash.HandlerFunc(pong))
	if err != nil {
		panic(err)
	}

	seed_url, err := s.SeedURL()
	if err != nil {
		panic(err)
	}

	fmt.Printf("seed with: %s\n", seed_url)

	err = s.Start()
	if err != nil {
		panic(err)
	}

	defer func() {
		err := s.Stop()
		if err != nil {
			panic(err)
		}
	}()

	for i := 1; i < len(os.Args); i++ {
		addr, key, err := telehash.ParseSeedURL(os.Args[i])
		if err != nil {
			fmt.Printf("invalid seed url: %s\n  %s\n", err, os.Args[i])
			continue
		}

		hn, err := s.Seed(addr, key)
		if err != nil {
			fmt.Printf("failed to seed: %s\n  %s\n", err, os.Args[i])
			continue
		}

		fmt.Printf("connected to %s\n", hn.Short())
	}

	peers := s.Seek(s.LocalHashname(), 15)
	for _, peer := range peers {
		fmt.Printf("discovered: %s\n", peer.Short())
	}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	fmt.Println("shutting down...")
}

func make_key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
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

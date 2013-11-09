package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/fd/go-util/log"
	"github.com/fd/gogotelehash"
	"os"
	"os/signal"
	"syscall"
)

func main() {
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

		fmt.Printf("connected to %s\n", hn[:8])
	}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}

func make_key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func pong(c *telehash.Channel) {
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

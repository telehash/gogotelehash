package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/telehash/gogotelehash"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	defer fmt.Println("BYE!")

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

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

	parse_main_seed(s)

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

func pong(c telehash.channel_i) {
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

// const seed = `
// [
//   {
//       "ip": "208.68.164.253",
//       "port": 42424,
//       "hashname": "5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088",
//       "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoQkh8uIPe18Ym5kO3VX\nqPhKsc7vhrMMH8HgUO3tSZeIcowHxZe+omFadTvquW4az7CV/+3EBVHWzuX90Vof\nsDsgbPXhzeV/TPOgrwz9B6AgEAq+UZ+cs5BSjZXXQgFrTHzEy9uboio+StBt3nB9\npLi/LlB0YNIoEk83neX++6dN63C3mSa55P8r4FvCWUXue2ZWfT6qamSGQeOPIUBo\n4aiN6P4Hzqaco6YRO9v901jV+nq0qp0yHKnxlIYgiY7501vXWceMtnqcEkgzX4Rr\n7nIoA6QnlUMkTUDP7N3ariNSwl8OL1ZjsFJz7XjfIJMQ+9kd1nNJ3sb4o3jOWCzj\nXwIDAQAB\n-----END PUBLIC KEY-----\n"
//   },
//   {
//     "IP": "87.236.178.46",
//     "Port": 45454,
//     "Hashname": "c32973bcdc0144040163b54aa3d1d5245bd302e400e10df0077c50104afaa274",
//     "Pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAwKqaofyr3E4kw1MZXGhc\nVG4Pk6Qm9xLQ4MlRgcaccqU9mqQlEFwokqhuksUa2/Cq22kiZpbx6bIts9RVZHyb\nME8Q6g0Af/+vVgmiQuF7F6It3d1HI3tQriXQSFf7JzanYHE4vzq2G1mE0sxfJE7Y\nO/UFCUt8v/w9m6Bogb4K7LZmFk1BVfkqxM+G7rS5j667JfTptXeYJjbZVdyej4K5\npTiGvCfqU+OFLxwR6uVdcoHrkuxwO89NX+ha2jgorTwPOt/LTQDHpqRtbnP5UXRa\n38d8OTqAT86LVWHi84+wPdcpA+9ZVSCYCIX6ThQCVWU+ltnKlE2Dl7AqQFSTXsbn\nuwIBIw==\n-----END PUBLIC KEY-----\n"
//   }
// ]
// `

// const seed = `
// [
// {
//     "ip": "208.68.164.253",
//     "port": 42424,
//     "hashname": "5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088",
//     "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoQkh8uIPe18Ym5kO3VX\nqPhKsc7vhrMMH8HgUO3tSZeIcowHxZe+omFadTvquW4az7CV/+3EBVHWzuX90Vof\nsDsgbPXhzeV/TPOgrwz9B6AgEAq+UZ+cs5BSjZXXQgFrTHzEy9uboio+StBt3nB9\npLi/LlB0YNIoEk83neX++6dN63C3mSa55P8r4FvCWUXue2ZWfT6qamSGQeOPIUBo\n4aiN6P4Hzqaco6YRO9v901jV+nq0qp0yHKnxlIYgiY7501vXWceMtnqcEkgzX4Rr\n7nIoA6QnlUMkTUDP7N3ariNSwl8OL1ZjsFJz7XjfIJMQ+9kd1nNJ3sb4o3jOWCzj\nXwIDAQAB\n-----END PUBLIC KEY-----\n"
// }
// ]
// `

// const seed = `
// [
//   {
//     "IP": "87.236.178.46",
//     "Port": 45454,
//     "Hashname": "c32973bcdc0144040163b54aa3d1d5245bd302e400e10df0077c50104afaa274",
//     "Pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAwKqaofyr3E4kw1MZXGhc\nVG4Pk6Qm9xLQ4MlRgcaccqU9mqQlEFwokqhuksUa2/Cq22kiZpbx6bIts9RVZHyb\nME8Q6g0Af/+vVgmiQuF7F6It3d1HI3tQriXQSFf7JzanYHE4vzq2G1mE0sxfJE7Y\nO/UFCUt8v/w9m6Bogb4K7LZmFk1BVfkqxM+G7rS5j667JfTptXeYJjbZVdyej4K5\npTiGvCfqU+OFLxwR6uVdcoHrkuxwO89NX+ha2jgorTwPOt/LTQDHpqRtbnP5UXRa\n38d8OTqAT86LVWHi84+wPdcpA+9ZVSCYCIX6ThQCVWU+ltnKlE2Dl7AqQFSTXsbn\nuwIBIw==\n-----END PUBLIC KEY-----\n"
//   }
// ]
// `

const seed = `
[
  {
    "IP": "95.85.6.236",
    "Port": 45454,
    "Hashname": "f3a2d1ff11f67069feac11bc562c32549e30135f56a9a9c6575499d6a7c72915",
    "Pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjmrFMFDApND2uOujSSN\nH9E1p8L65Doc4W8km61FPVtgtsGS/+1NLpFlIDo3c8FhvgVs+I2nPHd9WwvsXa5k\ngSzwSyBMUTFkIQGBlUbfo9vjdMm85iQt48r2JgKke15IyOsbsnzQYlIQ4s5h7ShF\nydt1JZyrbQgC5AxL5rD/vx9mTrd2k5oWiFnG8O1K6HVqrIJnZYc5Ts0hN+7nWHn+\ntuTCZEdtkx7LMqHnw6L4ylSjm7lBHAsIx1FCY+fRQYR+GGSvsBAYxrfsVoJUReuE\nLuuj/5oxeboon9C/CsNB6uI6tC8u1OjYHWG0xpY0bBaPOp5948XIUTXAokhH9fjd\ntQIDAQAB\n-----END PUBLIC KEY-----\n"
  }
]
`

func parse_main_seed(s *telehash.Switch) {
	var (
		seeds []struct {
			IP       string
			Port     int
			Hashname string
			Pubkey   string
		}
		pem_block *pem.Block
	)

	err := json.Unmarshal([]byte(seed), &seeds)
	if err != nil {
		panic(err)
	}

	for _, seed := range seeds {
		pem_block, _ = pem.Decode([]byte(seed.Pubkey))

		if pem_block.Type != "PUBLIC KEY" {
			continue
		}

		addr := fmt.Sprintf("%s:%d", seed.IP, seed.Port)

		keyi, err := x509.ParsePKIXPublicKey(pem_block.Bytes)
		if err != nil {
			fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
			continue
		}

		key, ok := keyi.(*rsa.PublicKey)
		if key == nil {
			fmt.Printf("failed to seed: %s\n  %s\n", "not an rsa key", addr)
			continue
		}
		if !ok {
			fmt.Printf("failed to seed: %s\n  %s\n", "not an rsa key", addr)
			continue
		}

		hn, err := s.Seed(addr, key)

		if err != nil {
			fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
			continue
		}

		fmt.Printf("connected to %s\n", hn.Short())
	}
}

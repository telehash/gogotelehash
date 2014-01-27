package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/dht/kademlia"
	"github.com/telehash/gogotelehash/net/http"
	"github.com/telehash/gogotelehash/net/ipv4"
	"github.com/telehash/gogotelehash/net/ipv6"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	seeds, err := telehash.LoadIdenities(env("SEED_FILE", "seeds.json"))
	assert(err)

	defer fmt.Println("BYE!")

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	addr := env("ADDR", ":4000")

	key := load_private_key(env("KEY_FILE", "./telehash_rsa"))

	s := &telehash.Switch{
		Key: key,
		Components: []telehash.Component{
			&ipv4.Transport{Addr: addr},
			&ipv6.Transport{Addr: addr},
			&http.Transport{PublicURL: "http://95.85.6.236:42425", ListenAddr: ":42425"},
			&kademlia.DHT{Seeds: seeds},
		},
	}

	assert(s.Start())

	fmt.Printf("Seed list:\n%s\n", make_seed_list(s))

	defer func() { assert(s.Stop()) }()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	fmt.Println("shutting down...")
}

func load_private_key(key_file string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(key_file)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(data)
	if block.Type != "RSA PRIVATE KEY" {
		panic("unsupport key file")
	}
	if x509.IsEncryptedPEMBlock(block) {
		panic("doesn't support encrypted rsa keys")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

func make_seed_list(sw *telehash.Switch) []byte {
	data, err := json.MarshalIndent(sw.Identity(), "", "  ")
	assert(err)
	return data
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

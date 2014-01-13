package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/telehash/gogotelehash"
	thnet "github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/http"
	"github.com/telehash/gogotelehash/net/ipv4"
	"github.com/telehash/gogotelehash/net/ipv6"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
)

func main() {
	defer fmt.Println("BYE!")

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":4000"
	}

	key := load_private_key()

	fmt.Printf("Seed list:\n%s\n", make_seed_list(addr, &key.PublicKey))

	s := &telehash.Switch{
		Key: key,
		Transports: []thnet.Transport{
			&ipv4.Transport{Addr: addr},
			&ipv6.Transport{Addr: addr},
			&http.Transport{PublicURL: "http://95.85.6.236:42425/", ListenAddr: ":42425"},
		},
	}

	err := s.Start()
	if err != nil {
		panic(err)
	}

	defer func() {
		err := s.Stop()
		if err != nil {
			panic(err)
		}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	fmt.Println("shutting down...")
}

func load_private_key() *rsa.PrivateKey {
	key_file := os.Getenv("KEY_FILE")
	if key_file == "" {
		key_file = "./telehash_rsa"
	}

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

func make_seed_list(addr string, key *rsa.PublicKey) []byte {

	var (
		seeds [1]struct {
			IP       string
			Port     int
			Hashname string
			Pubkey   string
		}
	)

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	hashname, err := telehash.HashnameFromPublicKey(key)
	if err != nil {
		panic(err)
	}

	ip, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}

	port, err := strconv.Atoi(portstr)
	if err != nil {
		panic(err)
	}

	seeds[0].IP = ip
	seeds[0].Port = port
	seeds[0].Hashname = hashname.String()
	seeds[0].Pubkey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	data, err := json.MarshalIndent(seeds, "", "  ")
	if err != nil {
		panic(err)
	}

	return data
}

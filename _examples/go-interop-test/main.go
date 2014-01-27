package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/dht/kademlia"
	"github.com/telehash/gogotelehash/net/ipv4"
	"github.com/telehash/gogotelehash/net/ipv6"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	app := cli.NewApp()
	app.Name = "go-interop-test"
	app.Usage = "Interop test for the 2013-12-10 meetup"
	app.Flags = []cli.Flag{
		cli.IntFlag{"port, p", 0, "The port to bind to."},
		cli.StringFlag{"seed, s", "", "The Seed file."},
		cli.StringFlag{"rsa-key", "", "The RSA private key."},
	}
	app.Commands = []cli.Command{
		{
			Name:   "run",
			Usage:  "Run the switch",
			Action: run,
		},
	}

	app.Run(os.Args)
}

func run(c *cli.Context) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var (
		key_file  = c.GlobalString("rsa-key")
		seed_file = c.GlobalString("seed")
		port      = c.GlobalInt("port")
		key       *rsa.PrivateKey
		sw        *telehash.Switch
		seeds     []*telehash.Identity
		err       error
	)

	if seed_file == "" && port == 0 {
		port = 42424
	}

	if key_file != "" {
		key = read_private_key(key_file)
	}

	if seed_file != "" {
		seeds, err = telehash.LoadIdenities(seed_file)
		assert(err)
	}

	sw = &telehash.Switch{
		Key: key,
		Components: []telehash.Component{
			&ipv4.Transport{Addr: fmt.Sprintf(":%d", port)},
			&ipv6.Transport{Addr: fmt.Sprintf(":%d", port)},
			&kademlia.DHT{Seeds: seeds},
		},
	}

	assert(sw.Start())
	defer func() { assert(sw.Stop()) }()

	fmt.Printf("\x1B[33m⚡ Starting switch on 0.0.0.0:%d\x1B[0m\n", port)
	fmt.Printf("\x1B[33m⚡ Seed with:\x1B[0m\n%s\n", make_seed_list(sw))

	wait_for_signal()

	fmt.Println("\r\x1B[2K\x1B[33m⚡ Goodbye\x1B[0m")
}

func wait_for_signal() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c

	fmt.Println("\r\x1B[2K\x1B[33m⚡ Received shutdown signal\x1B[0m")

	time.AfterFunc(15*time.Second, func() {
		fmt.Println("\r\x1B[2K\x1B[31m⚡ Unable to shutdown garcefully\x1B[0m")
		os.Exit(3)
	})
}

func read_private_key(fn string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		fmt.Printf("error: failed to read key file\n  %s\n", err)
		os.Exit(4)
	}

	block, _ := pem.Decode(data)
	if block.Type != "RSA PRIVATE KEY" {
		fmt.Printf("error: failed to parse key file\n  no private key found\n")
		os.Exit(4)
	}
	if x509.IsEncryptedPEMBlock(block) {
		fmt.Printf("error: failed to parse key file\n  encrypte PEM blocks are not supported\n")
		os.Exit(4)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("error: failed to parse key file\n  %s\n", err)
		os.Exit(4)
	}

	return key
}

func make_seed_list(sw *telehash.Switch) []byte {
	data, err := json.MarshalIndent(sw.Identity(), "", "  ")
	assert(err)
	return data
}

func assert(err error) {
	if err != nil {
		panic(err)
	}
}

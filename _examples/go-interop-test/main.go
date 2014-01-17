package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
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
		err       error
	)

	if seed_file == "" && port == 0 {
		port = 45454
	}

	if key_file != "" {
		key = read_private_key(key_file)
	}

	sw = &telehash.Switch{
		Key: key,
		Transports: []net.Transport{
			&ipv4.Transport{Addr: fmt.Sprintf("0.0.0.0:%d", port)},
			&ipv6.Transport{Addr: fmt.Sprintf("0.0.0.0:%d", port)},
		},
	}

	err = sw.Start()
	if err != nil {
		fmt.Printf("error: failed start switch\n  %s\n", err)
		os.Exit(2)
	}

	fmt.Printf("\x1B[33m⚡ Starting switch on 0.0.0.0:%d\x1B[0m\n", port)
	fmt.Printf("\x1B[33m⚡ Seed with:\x1B[0m\n%s\n", make_seed_list("0.0.0.0", port, &key.PublicKey))

	go func() {
		if seed_file != "" {
			for _, e := range read_seed_file(seed_file) {
				hn, err := sw.Seed("ipv4", e.addr, e.pubkey)
				if err != nil {
					fmt.Printf("error: failed to seed switch with %s\n  %s\n", hn.Short(), err)
					continue
				}
				fmt.Printf("\x1B[33m⚡ Seeded switch with %s\x1B[0m\n", hn.Short())
			}
		}
	}()

	wait_for_signal()

	err = sw.Stop()
	if err != nil {
		fmt.Printf("error: while terminating\n  %s\n", err)
		os.Exit(2)
	}

	fmt.Println("\r\x1B[2K\x1B[33m⚡ Goodbye\x1B[0m")
}

func wait_for_signal() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c

	fmt.Println("\r\x1B[2K\x1B[33m⚡ Received shutdown signal\x1B[0m")

	time.AfterFunc(5*time.Second, func() {
		fmt.Println("\r\x1B[2K\x1B[31m⚡ Unable to shutdown garcefully\x1B[0m")
		os.Exit(3)
	})
}

type SeedEntry struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Pubkey string `json:"pubkey"`
	addr   net.Addr
	pubkey *rsa.PublicKey
}

func read_seed_file(fn string) []*SeedEntry {
	var (
		list []*SeedEntry
	)

	f, err := os.Open(fn)
	if err != nil {
		fmt.Printf("error: failed to read seed file\n  %s\n", err)
		os.Exit(4)
	}

	err = json.NewDecoder(f).Decode(&list)
	if err != nil {
		fmt.Printf("error: failed to parse seed file\n  %s\n", err)
		os.Exit(4)
	}

	for _, e := range list {
		addr, err := ipv4.ResolveAddr(fmt.Sprintf("%s:%d", e.IP, e.Port))
		if err != nil {
			fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
			os.Exit(4)
		}

		e.addr = addr
		pem_block, _ := pem.Decode([]byte(e.Pubkey))

		if pem_block.Type != "PUBLIC KEY" {
			fmt.Printf("error: failed to parse public key\n  no public key found\n")
			os.Exit(4)
		}

		keyi, _ := x509.ParsePKIXPublicKey(pem_block.Bytes)

		key, ok := keyi.(*rsa.PublicKey)
		if key == nil {
			fmt.Printf("error: failed to parse public key\n  nil key\n")
			os.Exit(4)
		}
		if !ok {
			fmt.Printf("error: failed to parse public key\n  wrong key type %T\n", keyi)
			os.Exit(4)
		}

		e.pubkey = key
	}

	return list
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

func make_seed_list(ip string, port int, key *rsa.PublicKey) []byte {
	var (
		seeds [1]SeedEntry
	)

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	seeds[0].IP = ip
	seeds[0].Port = port
	seeds[0].Pubkey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	data, err := json.MarshalIndent(seeds, "", "  ")
	if err != nil {
		panic(err)
	}

	return data
}

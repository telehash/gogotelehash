package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/telehash/gogotelehash"
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
		seed_file = c.GlobalString("seed")
		port      = c.GlobalInt("port")
		key       *rsa.PrivateKey
		sw        *telehash.Switch
		err       error
	)

	if seed_file == "" && port == 0 {
		port = 45454
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("error: failed to generate a random key\n  %s\n", err)
	}

	sw, err = telehash.NewSwitch(fmt.Sprintf("0.0.0.0:%d", port), key, nil)
	if err != nil {
		fmt.Printf("error: failed start switch\n  %s\n", err)
	}

	sw.AllowRelay = false

	err = sw.Start()
	if err != nil {
		fmt.Printf("error: failed start switch\n  %s\n", err)
	}

	fmt.Printf("⚡ Staring switch on 0.0.0.0:%d\n", port)

	go func() {
		if seed_file != "" {
			for _, e := range read_seed_file(seed_file) {
				hn, err := sw.Seed(e.addr, e.pubkey)
				if err != nil {
					fmt.Printf("error: failed to seed switch with %s\n  %s\n", hn.Short(), err)
					continue
				}
				fmt.Printf("⚡ Seeded switch with %s\n", hn.Short())
			}
		}
	}()

	wait_for_signal()

	err = sw.Stop()
	if err != nil {
		fmt.Printf("error: while terminating\n  %s\n", err)
	}
}

func wait_for_signal() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c

	fmt.Println("\nreceined shutdown signal")

	time.AfterFunc(5*time.Second, func() {
		fmt.Println("unable to shutdown garcefully")
		os.Exit(3)
	})
}

type SeedEntry struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Pubkey string `json:"pubkey"`
	addr   string
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
		e.addr = fmt.Sprintf("%s:%d", e.IP, e.Port)

		pem_block, _ := pem.Decode([]byte(e.Pubkey))

		if pem_block.Type != "PUBLIC KEY" {
			fmt.Printf("error: failed to parse public key\n  %s\n", err)
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

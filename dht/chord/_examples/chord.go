package main

import (
	"log"

	"bitbucket.org/simonmenke/go-telehash/dht/chord"
	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"

	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
)

func main() {
	key, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	e := e3x.New(cipherset.Keys{0x3a: key})

	{
		t, err := udp.New(":0")
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		e.AddTransport(t)
	}

	err = e.Start()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	defer e.Stop()

	addr, err := e.LocalAddr()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	addrJSON, err := addr.MarshalJSON()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	log.Printf("addr:\n%s", addrJSON)

	ring, err := chord.Create(chord.DefaultConfig(addr.Hashname()), e)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	defer ring.Shutdown()
	defer ring.Leave()

	go join(addr)
	go join(addr)
	go join(addr)

	select {}
}

func join(entry *e3x.Addr) {
	key, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	e := e3x.New(cipherset.Keys{0x3a: key})

	{
		t, err := udp.New(":0")
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		e.AddTransport(t)
	}

	err = e.Start()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	defer e.Stop()

	addr, err := e.LocalAddr()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	ring, err := chord.Join(chord.DefaultConfig(addr.Hashname()), e, entry)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	defer ring.Shutdown()
	defer ring.Leave()

	select {}
}

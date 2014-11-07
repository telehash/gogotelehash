package main

import (
	"log"

	"github.com/telehash/gogotelehash/dht/chord"
	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/nat"
	"github.com/telehash/gogotelehash/transports/udp"
)

func main() {
	key, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	e := e3x.New(cipherset.Keys{0x3a: key},
		nat.Config{
			mux.Config{
				udp.Config{Network: "udp4"},
				udp.Config{Network: "udp6"},
			},
		})

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

	e := e3x.New(cipherset.Keys{0x3a: key}, mux.Config{
		udp.Config{Network: "udp4"},
		udp.Config{Network: "udp6"},
	})

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

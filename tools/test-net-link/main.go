package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
)

func main() {
	e := e3x.New(nil, mux.Config{
		udp.Config{Network: "udp4"},
		udp.Config{Network: "udp6"},
	})

	mesh.Register(e, nil)

	err := e.Start()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("golang: %s", e.LocalHashname())

	{
		var ident *e3x.Identity
		err := json.NewDecoder(os.Stdin).Decode(&ident)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("remote: %s", ident.Hashname())

		m := mesh.FromEndpoint(e)
		_, err = m.Link(ident, nil)
		if err != nil {
			log.Fatal(err)
		}

		time.Sleep(1 * time.Second)

	}

	err = e.Stop()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Bye")
}

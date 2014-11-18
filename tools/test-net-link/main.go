package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/modules/mesh"
)

func main() {
	e, err := e3x.Open(
		mesh.Module(nil))

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

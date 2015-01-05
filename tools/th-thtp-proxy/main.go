package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/modules/thtp"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/nat"
	"github.com/telehash/gogotelehash/transports/udp"
)

func main() {
	var peerIdentity *gogotelehash.Identity

	err := json.NewDecoder(os.Stdin).Decode(&peerIdentity)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	target, err := url.Parse("thtp://" + string(peerIdentity.Hashname()))
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	e, err := gogotelehash.Open(
		gogotelehash.Paths(),
		gogotelehash.Transport(nat.Config{
			mux.Config{
				udp.Config{Network: "udp4"},
				udp.Config{Network: "udp6"},
			},
		}))
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	{
		peerIdentityJSON, err := peerIdentity.MarshalJSON()
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		log.Printf("peerIdentity:\n%s", peerIdentityJSON)
	}

	tag, err := mesh.FromEndpoint(e).Link(peerIdentity, nil)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	thtp.RegisterDefaultTransport(e)
	go http.ListenAndServe(":3000", httputil.NewSingleHostReverseProxy(target))

	log.Printf("proxying to %s", peerIdentity.Hashname())

	{ // wait
		sig := make(chan os.Signal)
		go signal.Notify(sig, syscall.SIGTERM)
		<-sig
		signal.Stop(sig)
	}

	tag.Release()

	err = e.Close()
	if err != nil {
		log.Fatalf("error: %s", err)
	}
}

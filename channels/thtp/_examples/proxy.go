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
	"time"

	"github.com/telehash/gogotelehash/channels/thtp"
	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/nat"
	"github.com/telehash/gogotelehash/transports/udp"

	_ "github.com/telehash/gogotelehash/e3x/cipherset/cs3a"
)

func main() {
	var peerAddr *e3x.Addr

	err := json.NewDecoder(os.Stdin).Decode(&peerAddr)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	target, err := url.Parse("thtp://" + string(peerAddr.Hashname()))
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	k, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	e := e3x.New(
		cipherset.Keys{0x3a: k},
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

	time.Sleep(1 * time.Second)

	{
		peerAddrJSON, err := peerAddr.MarshalJSON()
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		log.Printf("peerAddr:\n%s", peerAddrJSON)
	}

	_, err = e.Dial(peerAddr)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	thtp.RegisterDefaultTransport(e)
	go http.ListenAndServe(":3000", httputil.NewSingleHostReverseProxy(target))

	log.Printf("proxying to %s", peerAddr.Hashname())

	{ // wait
		sig := make(chan os.Signal)
		go signal.Notify(sig, syscall.SIGTERM)
		<-sig
		signal.Stop(sig)
	}

	err = e.Stop()
	if err != nil {
		log.Fatalf("error: %s", err)
	}
}

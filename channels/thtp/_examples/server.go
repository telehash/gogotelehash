package main

import (
	"log"
	"net/http"
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
)

func main() {
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

	e.AddHandler("thtp", &thtp.Server{Handler: http.DefaultServeMux})

	err = e.Start()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	time.Sleep(1 * time.Second)

	addr, err := e.LocalAddr()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	addrJSON, err := addr.MarshalJSON()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	log.Printf("addr:\n%s", addrJSON)

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

func init() {

	// Hello Telehash!
	// Hǝʃʃo ⊥ǝʃǝɥɐsɥ¡
	//
	// - @fd
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rw.WriteHeader(200)
		rw.Write([]byte("Hello Telehash!\nHǝʃʃo ⊥ǝʃǝɥɐsɥ¡\n\n- @fd\n"))
	})

}

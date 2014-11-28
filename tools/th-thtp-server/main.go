package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/modules/netwatch"
	"github.com/telehash/gogotelehash/modules/paths"
	"github.com/telehash/gogotelehash/modules/thtp"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/nat"
	"github.com/telehash/gogotelehash/transports/udp"
)

func main() {
	e, err := e3x.Open(
		e3x.Log(nil),
		thtp.Server(http.DefaultServeMux),
		mesh.Module(nil),
		netwatch.Module(),
		paths.Module(),
		e3x.Transport(nat.Config{
			mux.Config{
				udp.Config{Network: "udp4"},
				udp.Config{Network: "udp6"},
			},
		}))
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	time.Sleep(20 * time.Second)

	identity, err := e.LocalIdentity()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	identityJSON, err := identity.MarshalJSON()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	log.Printf("identity:\n%s", identityJSON)

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

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

  "bitbucket.org/simonmenke/go-telehash/channels/thtp"
  "bitbucket.org/simonmenke/go-telehash/e3x"
  "bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
  "bitbucket.org/simonmenke/go-telehash/transports/mux"
  "bitbucket.org/simonmenke/go-telehash/transports/nat"
  "bitbucket.org/simonmenke/go-telehash/transports/udp"

  _ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
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

  {
    peerAddrJSON, err := peerAddr.MarshalJSON()
    if err != nil {
      log.Fatalf("error: %s", err)
    }

    log.Printf("peerAddr:\n%s", peerAddrJSON)
  }

  err = e.DialExchange(peerAddr)
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

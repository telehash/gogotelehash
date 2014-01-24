package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/ipv4"
	"github.com/telehash/gogotelehash/net/ipv6"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	sw := telehash.Switch{
		Handler: &proxy{},
		Transports: []net.Transport{
			&ipv4.Transport{Addr: ":0"},
			&ipv6.Transport{Addr: ":0"},
		},
	}

	must(sw.Start())
	defer sw.Stop()

	telehash.Log.Errorf("hashname=%s", sw.LocalHashname())

	parse_main_seed(&sw)

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type proxy struct {
	Handler http.Handler
}

func (r *proxy) ServeTelehash(channel *telehash.Channel) {
	telehash.Log.Errorf("req from=%s", channel.To())

	req, err := http.ReadRequest(bufio.NewReaderSize(channel, 1500))
	if err != nil {
		telehash.Log.Errorf("err=%s", err)
		return
	}

	telehash.Log.Errorf("req=%s", req.URL)

	req.RequestURI = ""
	req.URL.Host = req.Host
	req.URL.Scheme = "http"
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		telehash.Log.Errorf("err=%s", err)
		return
	}
	defer res.Body.Close()

	bw := bufio.NewWriterSize(channel, 1200)
	res.Write(bw)
	bw.Flush()
}

const seed = `
[
{
  "ip": "208.68.164.253",
  "port": 42424,
  "ip6": "2605:da00:5222:5269:230:48ff:fe35:6572",
  "port6": 42424,
  "hashname": "5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoQkh8uIPe18Ym5kO3VX\nqPhKsc7vhrMMH8HgUO3tSZeIcowHxZe+omFadTvquW4az7CV/+3EBVHWzuX90Vof\nsDsgbPXhzeV/TPOgrwz9B6AgEAq+UZ+cs5BSjZXXQgFrTHzEy9uboio+StBt3nB9\npLi/LlB0YNIoEk83neX++6dN63C3mSa55P8r4FvCWUXue2ZWfT6qamSGQeOPIUBo\n4aiN6P4Hzqaco6YRO9v901jV+nq0qp0yHKnxlIYgiY7501vXWceMtnqcEkgzX4Rr\n7nIoA6QnlUMkTUDP7N3ariNSwl8OL1ZjsFJz7XjfIJMQ+9kd1nNJ3sb4o3jOWCzj\nXwIDAQAB\n-----END PUBLIC KEY-----\n",
  "http": "http://208.68.164.253:42424",
  "bridge": true
}, {
  "ip": "173.255.220.185",
  "port": 42424,
  "ip6": "2600:3c01::f03c:91ff:fe70:ff59",
  "port6": 42424,
  "hashname": "b61120844c809260126aa0cf75390ef7f72c65a9ce03366efcf89ff549233758",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4xkpFtu9IQc/WiWNHGgm\nKnJ/TgiU9ltLLD4yJSu5LOiV5nH5lcjD8LPD4IgxPbOVKS/Xs2sosNqYsxVbSH60\nJ5EOzc3okIdTLj0OhDoEhpwBXpnWzRCYOqlRSeF78yu2oWxdP1zA9nMC7laB2veA\nDJ4KIaGKcs1uHesD5DGTGtPSHErove03HkMSlOBHpt239bNnv4XayQuwoRBsCoiT\ntKTPRxkbDN7KQtHozuumwq0wSedYoJe4r0Z36V6UU9KNnFvz2QR+CdRn3idDOeYj\nGnKFa5775fQGU5pwOk31u7J+gQ8h+tTQq6WZL5VaEeeFD6V4a6Zet2kBGhT6Z7h0\nuQIDAQAB\n-----END PUBLIC KEY-----\n"
}, {
  "ip": "204.45.252.101",
  "port": 42424,
  "hashname": "6b171cedc8945ca7ba078392c0d1bc34fe0e7f161fc60e7b1cdb246f68bcb683",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsXUyU223dwN5VbPZN9nn\niiQ7gTcTK90ad83I+/Nd6M87QF0qwHuF+cQYeQP2aJEfgZsFVCVVwcjRUxjRaVX/\nBSE4eKtIGazHr4idajkYka0No5hIJfw7p9INLZw6ALx4y9678sy2dyMAm0BHhY+A\n4AzlFd0uO+I3MJKED5DF0baACLNu9VdNIaRQ/OQeL/Jl1b4VJF/yZ6FZGcyYGYF7\nwf/ttSHMv1v1gCCC6o42Q2P67M+HpbPO1RD2IRrwmGI5Onmqp1bAqGmu4BMCfFsj\nn/mCVJnVVC1GNiUWQY6n549j2y7Ow7JKmRGlWq2i+QWSGOUylZIvue+XIObY7/dv\nPwIDAQAB\n-----END PUBLIC KEY-----\n"
}, {
  "ip": "208.126.199.195",
  "port": 42424,
  "ip6": "2001:470:c0a6:3::10",
  "port6": 42424,
  "hashname": "39c7f1d641947f51960ec5ab070680ea9dff110e8406cb07e4ae093a2e5d823a",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAltxAjgqbG441oAiqwF0p\nbJBUpPi06W1c0m3lrGg/h5nv5njiZq7s6LV9JZKPLINRk4UA4DdILBvOlKXG8/kQ\n0fMxve8di8EFbsaUCKaZ5zFWFYv1FPKc6TU29zIyQEGoZIZfphnfFUvk7PIOBd3m\nyEkncLBviFHVrfY3sDupni9ZOLGeAqpinQfuD1kmc3FbsZ+6j3A7QfMqlXI56jw3\nZRKrXyVL6eudj2FHL0ZO70m+MC3AcUBzXtwyDIY9xowIrcp6+dfSyQncGqKKDF3H\nqLRch+KpYrAZ6abHKjuN93tlIPyyKNCYQwex+j/UKN/5SlqDV8ctp4LwImCZQYGb\nLwIDAQAB\n-----END PUBLIC KEY-----\n",
  "http": "http://208.126.199.195:42424",
  "bridge": true
}, {
  "ip": "162.243.1.152",
  "port": 42424,
  "hashname": "9ba9c175c3c26af9df5c8163ea91d4ae4eca59ba95d66deb287c89ea0c596979",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnMrFnowz5jQAQrXSdj6M\nZE8mqbWweXwc53oe0kNC+AmBCnobYkdL4ZXk8JiHxP+sNtaTxbEagdQohoqTX1Ap\njjZ+pGt5Dcnqy1OfPMtUQyvEI1hL6xDU9msLPwK0NztHp1BlKeozppeBswNcPPxG\nevAn6yd51dP+BcrRAM34G8C+TrnNQWmBTRob1eKifDS+80taVxma5jt2/JUHFTxo\n2ualo4Wf/mScg8RXH4Pfhn7nIMBFQPom+58ERtORZWHl3aOty6It2inpPAx0PFBb\nNzBbYRMLOkW7IYfTdXz+Y17pM6kEWK1Y5xUHGmxTMY4IZtvX2L5bTTMhAdSYgqSF\nEQIDAQAB\n-----END PUBLIC KEY-----\n"
},
  {
    "IP": "95.85.6.236",
    "Port": 42424,
    "Hashname": "f3a2d1ff11f67069feac11bc562c32549e30135f56a9a9c6575499d6a7c72915",
    "Pubkey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjmrFMFDApND2uOujSSN\nH9E1p8L65Doc4W8km61FPVtgtsGS/+1NLpFlIDo3c8FhvgVs+I2nPHd9WwvsXa5k\ngSzwSyBMUTFkIQGBlUbfo9vjdMm85iQt48r2JgKke15IyOsbsnzQYlIQ4s5h7ShF\nydt1JZyrbQgC5AxL5rD/vx9mTrd2k5oWiFnG8O1K6HVqrIJnZYc5Ts0hN+7nWHn+\ntuTCZEdtkx7LMqHnw6L4ylSjm7lBHAsIx1FCY+fRQYR+GGSvsBAYxrfsVoJUReuE\nLuuj/5oxeboon9C/CsNB6uI6tC8u1OjYHWG0xpY0bBaPOp5948XIUTXAokhH9fjd\ntQIDAQAB\n-----END PUBLIC KEY-----\n"
  }
]
`

func parse_main_seed(s *telehash.Switch) {
	type seed_t struct {
		IP       string
		Port     int
		Hashname string
		Pubkey   string
	}
	var (
		seeds     []seed_t
		pem_block *pem.Block
	)

	err := json.Unmarshal([]byte(seed), &seeds)
	if err != nil {
		panic(err)
	}

	for _, seed := range seeds {
		go func(seed seed_t) {
			pem_block, _ = pem.Decode([]byte(seed.Pubkey))

			if pem_block.Type != "PUBLIC KEY" {
				return
			}

			addr, err := ipv4.ResolveAddr(fmt.Sprintf("%s:%d", seed.IP, seed.Port))
			if err != nil {
				fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
				return
			}

			keyi, err := x509.ParsePKIXPublicKey(pem_block.Bytes)
			if err != nil {
				fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
				return
			}

			key, ok := keyi.(*rsa.PublicKey)
			if key == nil {
				fmt.Printf("failed to seed: %s\n  %s\n", "not an rsa key", addr)
				return
			}
			if !ok {
				fmt.Printf("failed to seed: %s\n  %s\n", "not an rsa key", addr)
				return
			}

			hn, err := s.Seed("ipv4", addr, key)

			if err != nil {
				fmt.Printf("failed to seed: %s\n  %s\n", err, addr)
				return
			}

			fmt.Printf("connected to %s\n", hn.Short())
		}(seed)
	}
}

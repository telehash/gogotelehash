package main

import (
	"time"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/lob"
)

type TestPing struct{}

func (t *TestPing) Name() string {
	return "ping"
}

func (t *TestPing) Frequency() (min, max, time.Duration) {
	return 5 * time.Second, 10 * time.Second
}

func (t *TestPing) Setup(e *e3x.Endpoint) {
	e.AddHandler("ping", e3x.HandlerFunc(func(c *e3x.Channel) {
		defer c.Close()

		pkt, err := c.ReadPacket()
		if err != nil {
			return
		}

		if string(pkt.Body) != "ping" {
			return
		}

		pkt = &lob.Packet{Body: []byte("pong")}
		pkt.Header().SetBool("end", true)
		err = c.WritePacket(pkt)
		if err != nil {
			return
		}
	}))
}

func (t *TestPing) Run(e *e3x.Endpoint, r Reporter) {
	ch, err := e.Open(addr, "ping", false)
	if err != nil {
		r.Logf("Faild to open channel to %s", addr)
		r.Error(err)
		return
	}
	defer ch.Close()

	pkt := &lob.Packet{Body: []byte("ping")}
	err = c.WritePacket(pkt)
	if err != nil {
		r.Logf("Faild to send packet to %s", addr)
		r.Error(err)
		return
	}

	pkt, err = c.ReadPacket()
	if err != nil {
		r.Logf("Faild to read packet from %s", addr)
		r.Error(err)
		return
	}

	if string(pkt.Body) != "pong" {
		r.Errorf("%q is an invalid response expected `pong`", pkt.Body)
		return
	}
}

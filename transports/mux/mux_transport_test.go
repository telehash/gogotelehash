package mux

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

func TestManagerWithoutTransports(t *testing.T) {
	assert := assert.New(t)

	var (
		w    = make(chan transports.WriteOp)
		r    = make(chan transports.ReadOp)
		e    = make(chan events.E)
		done <-chan struct{}

		c   = Config{}
		tr  transports.Transport
		err error
	)

	go events.Log(nil, e)

	tr, err = c.Open()
	assert.NoError(err)
	assert.NotNil(tr)

	done = tr.Run(w, r, e)

	close(w)
	<-done
}

func TestManagerWithOneTransport(t *testing.T) {
	assert := assert.New(t)

	var (
		w    = make(chan transports.WriteOp)
		r    = make(chan transports.ReadOp)
		e    = make(chan events.E)
		done <-chan struct{}

		c   = Config{udp.Config{}}
		tr  transports.Transport
		err error
	)

	go events.Log(nil, e)

	tr, err = c.Open()
	assert.NoError(err)
	assert.NotNil(tr)

	done = tr.Run(w, r, e)

	close(w)
	<-done
}

func TestManagerDeliverReceive(t *testing.T) {
	assert := assert.New(t)

	var (
		eA    = make(chan events.E)
		wA    = make(chan transports.WriteOp)
		rA    = make(chan transports.ReadOp)
		doneA <-chan struct{}
		eB    = make(chan events.E)
		eB0   <-chan events.E
		eB1   <-chan events.E
		wB    = make(chan transports.WriteOp)
		rB    = make(chan transports.ReadOp)
		doneB <-chan struct{}

		ca  = Config{udp.Config{}}
		cb  = Config{udp.Config{Addr: "127.0.0.1:0"}}
		ta  transports.Transport
		tb  transports.Transport
		err error
	)

	ta, err = ca.Open()
	assert.NoError(err)
	assert.NotNil(ta)

	tb, err = cb.Open()
	assert.NoError(err)
	assert.NotNil(tb)

	doneA = ta.Run(wA, rA, eA)
	doneB = tb.Run(wB, rB, eB)

	eB0, eB1 = events.Split(eB)
	go events.Log(nil, events.Join(eA, eB1))
	addr := waitForFirstAddress(eB0)

	log.Printf("SND %q to %q", "Hello World!", addr)

	wop := transports.WriteOp{[]byte("Hello World!"), addr, make(chan error)}
	wA <- wop
	assert.NoError(<-wop.C)
	close(wA)

	rop := <-rB
	assert.NotNil(rop.Msg)
	assert.NotNil(rop.Src)
	assert.Equal("Hello World!", string(rop.Msg))
	log.Printf("RCV %q from %q", rop.Msg, rop.Src)
	close(wB)

	<-doneA
	<-doneB
}

func waitForFirstAddress(e <-chan events.E) transports.Addr {
	defer func() {
		go func() {
			for _ = range e {
			}
		}()
	}()

	for evt := range e {
		nc, ok := evt.(*transports.NetworkChangeEvent)
		if !ok || nc == nil {
			continue
		}
		if len(nc.Up) == 0 {
			continue
		}
		return nc.Up[0]
	}

	return nil
}

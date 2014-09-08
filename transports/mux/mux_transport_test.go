package mux

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

func TestManagerWithoutTransports(t *testing.T) {
	assert := assert.New(t)

	var (
		eventC = make(chan events.E)
		c      = Config{}
		tr     transports.Transport
		err    error
	)

	go events.Log(nil, eventC)

	tr, err = c.Open(eventC)
	assert.NoError(err)

	err = tr.Close()
	assert.NoError(err)

	err = tr.Close()
	assert.EqualError(err, transports.ErrClosed.Error())
}

func TestManagerWithOneTransport(t *testing.T) {
	assert := assert.New(t)

	var (
		eventC = make(chan events.E)
		c      = Config{udp.Config{}}
		tr     transports.Transport
		err    error
	)

	go events.Log(nil, eventC)

	tr, err = c.Open(eventC)
	assert.NoError(err)

	err = tr.Close()
	assert.NoError(err)
}

func TestManagerDeliverReceive(t *testing.T) {
	assert := assert.New(t)

	var (
		eventC = make(chan events.E)
		buf    = make([]byte, 1024)
		ca     = Config{udp.Config{}}
		cb     = Config{udp.Config{Addr: "127.0.0.1:0"}}
		ta     transports.Transport
		tb     transports.Transport
		err    error
	)

	go events.Log(nil, eventC)

	ta, err = ca.Open(eventC)
	defer ta.Close()
	assert.NoError(err)

	tb, err = cb.Open(eventC)
	defer tb.Close()
	assert.NoError(err)

	t.Logf("SND %q to %q", "Hello World!", tb.LocalAddresses()[0])

	err = ta.Deliver([]byte("Hello World!"), tb.LocalAddresses()[0])
	assert.NoError(err)

	n, addr, err := tb.Receive(buf)
	assert.NoError(err)
	assert.NotNil(addr)
	assert.Equal("Hello World!", string(buf[:n]))
	t.Logf("RCV %q from %q", buf[:n], addr)
}

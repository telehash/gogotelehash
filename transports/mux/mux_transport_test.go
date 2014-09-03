package mux

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
)

func TestManagerWithoutTransports(t *testing.T) {
	assert := assert.New(t)

	var (
		c   = Config{}
		tr  transports.Transport
		err error
	)

	tr, err = c.Open()
	assert.NoError(err)

	err = tr.Close()
	assert.NoError(err)

	err = tr.Close()
	assert.EqualError(err, transports.ErrClosed.Error())
}

func TestManagerWithOneTransport(t *testing.T) {
	assert := assert.New(t)

	var (
		c   = Config{udp.Config{}}
		tr  transports.Transport
		err error
	)

	tr, err = c.Open()
	assert.NoError(err)

	err = tr.Close()
	assert.NoError(err)
}

func TestManagerDeliverReceive(t *testing.T) {
	assert := assert.New(t)

	var (
		buf = make([]byte, 1024)
		ca  = Config{udp.Config{}}
		cb  = Config{udp.Config{Addr: "127.0.0.1:0"}}
		ta  transports.Transport
		tb  transports.Transport
		err error
	)

	ta, err = ca.Open()
	defer ta.Close()
	assert.NoError(err)

	tb, err = cb.Open()
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

package transports_test

import (
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
)

func TestManagerWithoutTransports(t *testing.T) {
	assert := assert.New(t)

	var m transports.Manager
	assert.Equal(transports.UnknownManagerState, m.State())

	err := m.Start()
	assert.NoError(err)
	assert.Equal(transports.RunningManagerState, m.State())

	err = m.Stop()
	assert.NoError(err)
	assert.Equal(transports.TerminatedManagerState, m.State())
}

func TestManagerWithOneTransport(t *testing.T) {
	assert := assert.New(t)

	var m transports.Manager
	assert.Equal(transports.UnknownManagerState, m.State())

	m.AddTransport(udp.Config{})

	assert.Equal(transports.UnknownManagerState, m.State())

	err := m.Start()
	assert.NoError(err)
	assert.Equal(transports.RunningManagerState, m.State())

	err = m.Stop()
	assert.NoError(err)
	assert.Equal(transports.TerminatedManagerState, m.State())
}

func TestManagerDeliverReceive(t *testing.T) {
	assert := assert.New(t)

	var (
		ma transports.Manager
		mb transports.Manager
	)

	ma.AddTransport(udp.Config{})
	mb.AddTransport(udp.Config{Addr: "127.0.0.1:0"})

	err := ma.Start()
	defer ma.Stop()
	assert.NoError(err)

	err = mb.Start()
	defer mb.Stop()
	assert.NoError(err)

	t.Logf("SND %q to %q", "Hello Wolrd!", mb.LocalAddresses()[0])

	err = ma.Deliver([]byte("Hello Wolrd!"), mb.LocalAddresses()[0])
	assert.NoError(err)

	msg, addr, err := mb.Receive()
	assert.NoError(err)
	assert.NotNil(addr)
	assert.Equal("Hello Wolrd!", string(msg))
	t.Logf("RCV %q from %q", msg, addr)
}

func TestManagerResolveAll(t *testing.T) {
	assert := assert.New(t)

	var (
		ma transports.Manager
		mb transports.Manager
	)

	ma.AddTransport(udp.Config{})
	mb.AddTransport(udp.Config{Addr: "127.0.0.1:0"})

	err := ma.Start()
	defer ma.Stop()
	assert.NoError(err)

	err = mb.Start()
	defer mb.Stop()
	assert.NoError(err)

	ma.Associate(hashname.H("node-a"), mb.LocalAddresses()[0])

	t.Logf("SND %q to %q", "Hello Wolrd!", transports.All(hashname.H("node-a")))

	err = ma.Deliver([]byte("Hello Wolrd!"), transports.All(hashname.H("node-a")))
	assert.NoError(err)

	time.AfterFunc(5*time.Second, func() { mb.Stop() })

	for {
		msg, addr, err := mb.Receive()
		if err == transports.ErrManagerTerminated {
			break
		}
		assert.NoError(err)
		assert.NotNil(addr)
		assert.Equal("Hello Wolrd!", string(msg))
		if err != nil {
			break
		}

		t.Logf("RCV %q from %q", msg, addr)
	}
}

func TestManagerResolveBest(t *testing.T) {
	assert := assert.New(t)

	var (
		ma transports.Manager
		mb transports.Manager
	)

	ma.AddTransport(udp.Config{})
	mb.AddTransport(udp.Config{Addr: "127.0.0.1:0"})

	err := ma.Start()
	defer ma.Stop()
	assert.NoError(err)

	err = mb.Start()
	defer mb.Stop()
	assert.NoError(err)

	ma.Associate(hashname.H("node-a"), mb.LocalAddresses()[0])

	t.Logf("SND %q to %q", "Hello Wolrd!", transports.Best(hashname.H("node-a")))

	err = ma.Deliver([]byte("Hello Wolrd!"), transports.Best(hashname.H("node-a")))
	assert.NoError(err)

	time.AfterFunc(5*time.Second, func() { mb.Stop() })

	for {
		msg, addr, err := mb.Receive()
		if err == transports.ErrManagerTerminated {
			break
		}
		assert.NoError(err)
		assert.NotNil(addr)
		assert.Equal("Hello Wolrd!", string(msg))
		if err != nil {
			break
		}

		t.Logf("RCV %q from %q", msg, addr)
	}
}

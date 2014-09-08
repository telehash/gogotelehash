package e3x

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/transports/mux"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

func TestSimpleEndpoint(t *testing.T) {
	assert := assert.New(t)

	eventC := make(chan events.E)
	go events.Log(nil, eventC)

	ka, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	kb, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	ea := New(cipherset.Keys{0x3a: ka}, mux.Config{udp.Config{}})
	eb := New(cipherset.Keys{0x3a: kb}, mux.Config{udp.Config{}})

	ea.Subscribe(eventC)
	eb.Subscribe(eventC)

	err = ea.Start()
	assert.NoError(err)

	err = eb.Start()
	assert.NoError(err)

	addrA, err := ea.LocalAddr()
	assert.NoError(err)

	addrB, err := eb.LocalAddr()
	assert.NoError(err)

	tracef("HELLO")
	err = ea.DialExchange(addrB)
	assert.NoError(err)

	err = ea.DialExchange(addrB)
	assert.NoError(err)

	err = eb.DialExchange(addrA)
	assert.NoError(err)

	time.Sleep(2*time.Minute + 10*time.Second)
	tracef("BYE")

	tracef("ea: schedule idle=%v next=%s", ea.scheduler.Idle(), ea.scheduler.Next())
	tracef("eb: schedule idle=%v next=%s", eb.scheduler.Idle(), eb.scheduler.Next())

	err = ea.Stop()
	assert.NoError(err)

	err = eb.Stop()
	assert.NoError(err)
}

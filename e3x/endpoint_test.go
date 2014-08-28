package e3x

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
)

func TestSimpleEndpoint(t *testing.T) {
	assert := assert.New(t)

	ka, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	kb, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	ta, err := udp.New("")
	assert.NoError(err)

	tb, err := udp.New("127.0.0.1:8081")
	assert.NoError(err)

	ea := New(cipherset.Keys{0x3a: ka})
	eb := New(cipherset.Keys{0x3a: kb})

	ea.AddTransport(ta)
	eb.AddTransport(tb)

	err = ea.Start()
	assert.NoError(err)

	err = eb.Start()
	assert.NoError(err)

	addrA, err := NewAddr(cipherset.Keys{0x3a: ka}, nil, ta.LocalAddresses())
	assert.NoError(err)

	addrB, err := NewAddr(cipherset.Keys{0x3a: kb}, nil, tb.LocalAddresses())
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

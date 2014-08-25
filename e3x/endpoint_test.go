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

	time.AfterFunc(10*time.Second, func() { panic("OOPS") })

	err = ea.Start()
	assert.NoError(err)

	err = eb.Start()
	assert.NoError(err)

	err = ea.Dial(cipherset.Keys{0x3a: kb}, tb.LocalAddresses())
	assert.NoError(err)

	err = ea.Dial(cipherset.Keys{0x3a: kb}, tb.LocalAddresses())
	assert.NoError(err)

	err = eb.Dial(cipherset.Keys{0x3a: ka}, ta.LocalAddresses())
	assert.NoError(err)

	time.Sleep(5 * time.Second)

	err = ea.Stop()
	assert.NoError(err)

	err = eb.Stop()
	assert.NoError(err)
}

package e3x

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	_ "github.com/telehash/gogotelehash/e3x/cipherset/cs3a"
	"github.com/telehash/gogotelehash/transports/inproc"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
)

func TestSimpleEndpoint(t *testing.T) {
	logs.ResetLogger()

	if testing.Short() {
		t.Skip("this is a long running test.")
	}

	assert := assert.New(t)

	ka, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	kb, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	ea := New(cipherset.Keys{0x3a: ka}, mux.Config{udp.Config{}, inproc.Config{}})
	eb := New(cipherset.Keys{0x3a: kb}, mux.Config{udp.Config{}, inproc.Config{}})

	registerEventLoggers(ea, t)
	registerEventLoggers(eb, t)

	err = ea.Start()
	assert.NoError(err)

	err = eb.Start()
	assert.NoError(err)

	time.Sleep(1 * time.Second)

	identA, err := ea.LocalIdentity()
	assert.NoError(err)

	identB, err := eb.LocalIdentity()
	assert.NoError(err)

	tracef("HELLO")
	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = eb.Dial(identA)
	assert.NoError(err)

	time.Sleep(2*time.Minute + 10*time.Second)
	tracef("BYE")

	err = ea.Stop()
	assert.NoError(err)

	err = eb.Stop()
	assert.NoError(err)
}

package e3x

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x/cipherset"
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

	ea, erra := Open(
		Keys(cipherset.Keys{0x3a: ka}),
		Transport(mux.Config{udp.Config{}, inproc.Config{}}),
		Log(nil))

	eb, errb := Open(
		Keys(cipherset.Keys{0x3a: kb}),
		Transport(mux.Config{udp.Config{}, inproc.Config{}}),
		Log(nil))
	assert.NoError(erra)
	assert.NoError(errb)

	time.Sleep(1 * time.Second)

	identA, err := ea.LocalIdentity()
	assert.NoError(err)

	identB, err := eb.LocalIdentity()
	assert.NoError(err)

	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = eb.Dial(identA)
	assert.NoError(err)

	time.Sleep(2*time.Minute + 10*time.Second)

	err = ea.Stop()
	assert.NoError(err)

	err = eb.Stop()
	assert.NoError(err)
}

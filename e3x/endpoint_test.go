package e3x

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/transports/inproc"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
)

func TestSimpleEndpoint(t *testing.T) {
	t.Parallel()
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
		Keys(map[cipherset.CSID]*cipherset.PrivateKey{0x3a: ka}),
		Transport(mux.Config{udp.Config{}, inproc.Config{}}),
		Log(nil))

	eb, errb := Open(
		Keys(map[cipherset.CSID]*cipherset.PrivateKey{0x3a: kb}),
		Transport(mux.Config{udp.Config{}, inproc.Config{}}),
		Log(nil))
	assert.NoError(erra)
	assert.NoError(errb)

	time.Sleep(1 * time.Second)

	identA := ea.LocalIdentity()
	identB := eb.LocalIdentity()

	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = ea.Dial(identB)
	assert.NoError(err)

	_, err = eb.Dial(identA)
	assert.NoError(err)

	time.Sleep(2*time.Minute + 10*time.Second)

	err = ea.Close()
	assert.NoError(err)

	err = eb.Close()
	assert.NoError(err)
}

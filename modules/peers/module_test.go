package peers

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/modules/bridge"
	"github.com/telehash/gogotelehash/transports/udp"

	_ "github.com/telehash/gogotelehash/e3x/cipherset/cs1a"
	_ "github.com/telehash/gogotelehash/e3x/cipherset/cs3a"
)

var log = logs.Module("test")

func TestPeers(t *testing.T) {
	assert := assert.New(t)

	A, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		mesh.Module(nil),
		Module(Config{}))
	assert.NoError(err)

	B, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		mesh.Module(nil),
		Module(Config{}))
	assert.NoError(err)

	R, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		bridge.Module(),
		mesh.Module(nil),
		Module(Config{}))
	assert.NoError(err)

	var BR_tag mesh.Tag
	{
		ident, err := R.LocalIdentity()
		if assert.NoError(err) {
			m := mesh.FromEndpoint(B)
			BR_tag, err = m.Link(ident, nil)
			if assert.NoError(err) {
				log.Println("acquired link")
			}
		}
	}

	{
		ident, err := R.LocalIdentity()
		if assert.NoError(err) {
			peers := FromEndpoint(A)
			ex, err := peers.IntroduceVia(B.LocalHashname(), ident)
			assert.NoError(err)
			assert.NotNil(ex)
		}
	}

	fase1 := time.After(130 * time.Second) // should stay alive for atleast 2 minutes
	fase2 := time.After(260 * time.Second) // after two more minutes the exchange must expire
	<-fase1

	log.Println("releasing the link")
	BR_tag.Release()
	<-fase2

	assert.NoError(A.Close())
	assert.NoError(B.Close())
	assert.NoError(R.Close())
}

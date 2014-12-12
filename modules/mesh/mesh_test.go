package mesh

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
)

var log = logs.Module("test")

func TestPeers(t *testing.T) {
	assert := assert.New(t)

	A, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		Module(nil))
	assert.NoError(err)
	B, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		Module(nil))
	assert.NoError(err)

	var AB_tag Tag
	{
		ident, err := B.LocalIdentity()
		if assert.NoError(err) {
			m := FromEndpoint(A)
			AB_tag, err = m.Link(ident, nil)
			if assert.NoError(err) {
				log.Println("acquired link")
			}
		}
	}

	fase1 := time.After(130 * time.Second) // should stay alive for atleast 2 minutes
	fase2 := time.After(260 * time.Second) // after two more minutes the exchange must expire
	<-fase1

	log.Println("releasing the link")
	AB_tag.Release()

	<-fase2

	assert.NoError(A.Close())
	assert.NoError(B.Close())
}

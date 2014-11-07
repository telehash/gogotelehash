package mesh

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
)

var log = logs.Module("test")

func TestPeers(t *testing.T) {
	assert := assert.New(t)

	A := e3x.New(randomKeys(0x3a, 0x1a), udp.Config{})
	B := e3x.New(randomKeys(0x3a, 0x1a), udp.Config{})

	Register(A, nil)
	Register(B, nil)

	assert.NoError(A.Start())
	assert.NoError(B.Start())

	var AB_tag Tag
	{
		ident, err := B.LocalIdent()
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

	assert.NoError(A.Stop())
	assert.NoError(B.Stop())
}

func randomKeys(csids ...uint8) cipherset.Keys {
	keys := cipherset.Keys{}

	for _, csid := range csids {
		key, err := cipherset.GenerateKey(csid)
		if err != nil {
			panic(err)
		}
		keys[csid] = key
	}

	return keys
}

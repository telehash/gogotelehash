package uri

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports/udp"
)

func Test_resolveHTTP(t *testing.T) {
	assert := assert.New(t)

	e := e3x.New(randomKeys(0x3a, 0x1a), udp.Config{})
	err := e.Start()
	if err != nil {
		panic(err)
	}
	defer e.Stop()

	s := httptest.NewServer(WellKnown(e))
	defer s.Close()

	uri, err := Parse(s.URL[7:])
	if err != nil {
		panic(err)
	}

	ident, err := resolveHTTP(uri)
	assert.NoError(err)
	assert.NotNil(ident)
	t.Logf("ident=%v addrs=%v keys=%v", ident, ident.Addresses(), ident.Keys())
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

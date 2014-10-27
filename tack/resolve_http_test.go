package tack

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
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

	tack, err := Parse("app:" + s.URL[7:])
	if err != nil {
		panic(err)
	}

	ident, err := resolveHTTP(tack)
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

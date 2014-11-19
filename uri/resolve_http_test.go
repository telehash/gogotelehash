package uri

import (
	"net/http/httptest"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
)

func Test_resolveHTTP(t *testing.T) {
	assert := assert.New(t)

	e, err := e3x.Open()
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

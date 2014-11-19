package uri

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	_ "github.com/telehash/gogotelehash/e3x"
)

func TestResolve(t *testing.T) {
	assert := assert.New(t)

	uri, err := Parse("01.test.simonmenke.me")
	if err != nil {
		panic(err)
	}

	ident, err := Resolve(uri)
	assert.NoError(err)
	assert.NotNil(ident)
	t.Logf("ident=%v addrs=%v keys=%v", ident, ident.Addresses(), ident.Keys())
}

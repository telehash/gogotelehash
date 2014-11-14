package unix

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
)

func TestLocalAddresses(t *testing.T) {
	assert := assert.New(t)
	var tab = []Config{
		{},
		{Name: "/tmp/telehash-test.sock"},
	}

	for _, factory := range tab {
		trans, err := factory.Open()
		if assert.NoError(err) && assert.NotNil(trans) {
			addrs := trans.LocalAddresses()
			assert.NotEmpty(addrs)

			t.Logf("factory=%v addrs=%v", factory, addrs)
			err = trans.Close()
			assert.NoError(err)
		}
	}
}

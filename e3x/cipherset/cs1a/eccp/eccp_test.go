package eccp

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x/cipherset/cs1a/secp160r1"
)

func Test_Marshal_Unmarshal_P256(t *testing.T) {
	assert := assert.New(t)

	for i := 100; i > 0; i-- {
		_, x1, y1, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NoError(err)
		assert.NotNil(x1)
		assert.NotNil(y1)

		data := Marshal(elliptic.P256(), x1, y1)
		assert.NotNil(data)

		x2, y2 := Unmarshal(elliptic.P256(), data)
		assert.NotNil(x2)
		assert.NotNil(y2)

		assert.Equal(x1.Bytes(), x2.Bytes())
		assert.Equal(y1.Bytes(), y2.Bytes())
	}
}

func Test_Marshal_Unmarshal_P160(t *testing.T) {
	assert := assert.New(t)

	for i := 100; i > 0; i-- {
		_, x1, y1, err := elliptic.GenerateKey(secp160r1.P160(), rand.Reader)
		assert.NoError(err)
		assert.NotNil(x1)
		assert.NotNil(y1)

		data := Marshal(secp160r1.P160(), x1, y1)
		assert.NotNil(data)

		x2, y2 := Unmarshal(secp160r1.P160(), data)
		assert.NotNil(x2)
		assert.NotNil(y2)

		assert.Equal(x1.Bytes(), x2.Bytes())
		assert.Equal(y1.Bytes(), y2.Bytes())
	}
}

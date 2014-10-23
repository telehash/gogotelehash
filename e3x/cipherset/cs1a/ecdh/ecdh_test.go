package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a/secp160r1"
)

func Test_ComputeShared_P256(t *testing.T) {
	assert := assert.New(t)
	curve := elliptic.P256()

	for i := 100; i > 0; i-- {
		prv1, x1, y1, err := elliptic.GenerateKey(curve, rand.Reader)
		assert.NoError(err)
		assert.NotNil(prv1)
		assert.NotNil(x1)
		assert.NotNil(y1)

		prv2, x2, y2, err := elliptic.GenerateKey(curve, rand.Reader)
		assert.NoError(err)
		assert.NotNil(prv2)
		assert.NotNil(x2)
		assert.NotNil(y2)

		shared1 := ComputeShared(curve, x2, y2, prv1)
		shared2 := ComputeShared(curve, x1, y1, prv2)

		assert.Equal(shared1, shared2)
	}
}

func Test_ComputeShared_P160(t *testing.T) {
	assert := assert.New(t)
	curve := secp160r1.P160()

	for i := 100; i > 0; i-- {
		prv1, x1, y1, err := elliptic.GenerateKey(curve, rand.Reader)
		assert.NoError(err)
		assert.NotNil(prv1)
		assert.NotNil(x1)
		assert.NotNil(y1)

		prv2, x2, y2, err := elliptic.GenerateKey(curve, rand.Reader)
		assert.NoError(err)
		assert.NotNil(prv2)
		assert.NotNil(x2)
		assert.NotNil(y2)

		shared1 := ComputeShared(curve, x2, y2, prv1)
		shared2 := ComputeShared(curve, x1, y1, prv2)

		assert.Equal(shared1, shared2)
	}
}

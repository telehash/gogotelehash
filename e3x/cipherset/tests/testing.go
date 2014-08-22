package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
)

type cipherTestSuite struct {
	suite.Suite
	cipher cipherset.Cipher
}

func Run(t *testing.T, c cipherset.Cipher) {
	suite.Run(t, &cipherTestSuite{cipher: c})
}

func (s *cipherTestSuite) TestMessage() {
	var (
		assert = s.Assertions
		c      = s.cipher
	)

	var (
		ka  cipherset.Key
		kb  cipherset.Key
		box = make([]byte, 3, 1500)
		seq uint32
		msg []byte
		err error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	kb, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(kb)

	box, err = c.EncryptMessage(kb, ka, nil, 1, []byte("Hello World!"), box)
	assert.NoError(err)
	assert.NotNil(box)

	seq, msg, err = c.DecryptMessage(kb, ka, box)
	assert.NoError(err)
	assert.NotNil(msg)
	assert.Equal([]byte("Hello World!"), msg)
	assert.Equal(1, seq)
}

func (s *cipherTestSuite) TestHandshake() {
	var (
		assert = s.Assertions
		c      = s.cipher
	)

	var (
		ka  cipherset.Key
		kb  cipherset.Key
		kc  cipherset.Key
		box = make([]byte, 3, 1500)
		seq uint32
		msg []byte
		err error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	kb, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(kb)

	box, err = c.EncryptHandshake(kb, ka, nil, 1, box)
	assert.NoError(err)
	assert.NotNil(box)

	seq, kc, err = c.DecryptHandshake(kb, box)
	assert.NoError(err)
	assert.NotNil(kc)
	assert.Equal(ka.Bytes(), kc.Bytes())
	assert.Equal(1, seq)

	// handshake is also a message
	seq, msg, err = c.DecryptMessage(kb, ka, box)
	assert.NoError(err)
	assert.NotNil(msg)
	assert.Equal(ka.Bytes(), msg)
	assert.Equal(1, seq)

	box, err = c.EncryptMessage(kb, ka, nil, 1, ka.Bytes(), box)
	assert.NoError(err)
	assert.NotNil(box)

	seq, kc, err = c.DecryptHandshake(kb, box)
	assert.NoError(err)
	assert.NotNil(kc)
	assert.Equal(ka.Bytes(), kc.Bytes())
	assert.Equal(1, seq)
}

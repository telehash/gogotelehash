package tests

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/lob"
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
		sa  cipherset.State
		sb  cipherset.State
		seq uint32
		box []byte
		msg []byte
		err error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	sa, err = c.NewState(ka, true)
	assert.NoError(err)
	assert.NotNil(sa)
	assert.False(sa.CanEncryptMessage())
	assert.False(sa.CanEncryptHandshake())
	assert.False(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.True(sa.NeedsRemoteKey())

	kb, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(kb)

	sb, err = c.NewState(kb, false)
	assert.NoError(err)
	assert.NotNil(sb)
	assert.False(sb.CanEncryptMessage())
	assert.False(sb.CanEncryptHandshake())
	assert.False(sb.CanDecryptMessage())
	assert.True(sb.CanDecryptHandshake())
	assert.True(sb.NeedsRemoteKey())

	err = sa.SetRemoteKey(kb)
	assert.NoError(err)
	assert.True(sa.CanEncryptMessage())
	assert.True(sa.CanEncryptHandshake())
	assert.True(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.False(sa.NeedsRemoteKey())

	err = sb.SetRemoteKey(ka)
	assert.NoError(err)
	assert.True(sb.CanEncryptMessage())
	assert.True(sb.CanEncryptHandshake())
	assert.True(sb.CanDecryptMessage())
	assert.True(sb.CanDecryptHandshake())
	assert.False(sb.NeedsRemoteKey())

	box, err = sa.EncryptMessage(1, []byte("Hello World!"))
	assert.NoError(err)
	assert.NotNil(box)

	seq, msg, err = sb.DecryptMessage(box)
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
		ka      cipherset.Key
		kb      cipherset.Key
		kc      cipherset.Key
		sa      cipherset.State
		sb      cipherset.State
		seq     uint32
		box     []byte
		compact cipherset.Parts
		err     error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	sa, err = c.NewState(ka, true)
	assert.NoError(err)
	assert.NotNil(sa)
	assert.False(sa.CanEncryptMessage())
	assert.False(sa.CanEncryptHandshake())
	assert.False(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.True(sa.NeedsRemoteKey())

	kb, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(kb)

	sb, err = c.NewState(kb, false)
	assert.NoError(err)
	assert.NotNil(sb)
	assert.False(sb.CanEncryptMessage())
	assert.False(sb.CanEncryptHandshake())
	assert.False(sb.CanDecryptMessage())
	assert.True(sb.CanDecryptHandshake())
	assert.True(sb.NeedsRemoteKey())

	err = sa.SetRemoteKey(kb)
	assert.NoError(err)
	assert.True(sa.CanEncryptMessage())
	assert.True(sa.CanEncryptHandshake())
	assert.True(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.False(sa.NeedsRemoteKey())

	box, err = sa.EncryptHandshake(1, cipherset.Parts{0x01: "foobarzzzzfoobarzzzzfoobarzzzzfoobarzzzzfoobarzzzz34"})
	assert.NoError(err)
	assert.NotNil(box)

	seq, kc, compact, err = sb.DecryptHandshake(box)
	assert.NoError(err)
	assert.NotNil(kc)
	assert.Equal(ka.Bytes(), kc.Bytes())
	assert.Equal(cipherset.Parts{0x01: "foobarzzzzfoobarzzzzfoobarzzzzfoobarzzzzfoobarzzzz34"}, compact)
	assert.Equal(1, seq)
	assert.True(sb.CanEncryptMessage())
	assert.True(sb.CanEncryptHandshake())
	assert.True(sb.CanDecryptMessage())
	assert.True(sb.CanDecryptHandshake())
	assert.False(sb.NeedsRemoteKey())

	tb := sb.RemoteToken()
	assert.Equal(box[4:4+16], tb[:])
}

func (s *cipherTestSuite) TestPacketEncryption() {
	var (
		assert = s.Assertions
		c      = s.cipher
	)

	var (
		ka  cipherset.Key
		kb  cipherset.Key
		sa  cipherset.State
		sb  cipherset.State
		pkt *lob.Packet
		box []byte
		err error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	kb, err = c.GenerateKey()
	assert.NoError(err)

	sa, err = c.NewState(ka, true)
	assert.NoError(err)
	sb, err = c.NewState(kb, false)
	assert.NoError(err)

	err = sa.SetRemoteKey(kb)
	assert.NoError(err)
	box, err = sa.EncryptHandshake(1, nil)
	assert.NoError(err)
	_, _, _, err = sb.DecryptHandshake(box)
	assert.NoError(err)
	box, err = sb.EncryptHandshake(1, nil)
	assert.NoError(err)
	_, _, _, err = sa.DecryptHandshake(box)
	assert.NoError(err)

	pkt, err = sa.EncryptPacket(&lob.Packet{
		Json: map[string]int{"foo": 0xbeaf},
		Body: []byte("Hello world!"),
	})
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Nil(pkt.Json)
	assert.NotEmpty(pkt.Body)

	pkt, err = sb.DecryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Equal(map[string]interface{}{"foo": 0xbeaf}, pkt.Json)
	assert.Equal([]byte("Hello world!"), pkt.Body)

	pkt, err = sb.EncryptPacket(&lob.Packet{
		Json: map[string]int{"bar": 0xdead},
		Body: []byte("Bye world!"),
	})
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Nil(pkt.Json)
	assert.NotEmpty(pkt.Body)

	pkt, err = sa.DecryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Equal(map[string]interface{}{"bar": 0xdead}, pkt.Json)
	assert.Equal([]byte("Bye world!"), pkt.Body)
}

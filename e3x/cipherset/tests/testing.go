package tests

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/suite"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/lob"
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
		box []byte
		msg []byte
		err error
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	sa, err = c.NewState(ka)
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

	err = sa.SetRemoteKey(kb)
	assert.NoError(err)
	assert.True(sa.CanEncryptMessage())
	assert.True(sa.CanEncryptHandshake())
	assert.True(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.False(sa.NeedsRemoteKey())

	box, err = sa.EncryptMessage([]byte("Hello World!"))
	assert.NoError(err)
	assert.NotNil(box)

	msg, err = c.DecryptMessage(kb, ka, box)
	assert.NoError(err)
	assert.NotNil(msg)
	assert.Equal([]byte("Hello World!"), msg)
}

func (s *cipherTestSuite) TestHandshake() {
	var (
		assert = s.Assertions
		c      = s.cipher
	)

	var (
		ka  cipherset.Key
		kb  cipherset.Key
		sa  cipherset.State
		sb  cipherset.State
		ha  cipherset.Handshake
		hb  cipherset.Handshake
		box []byte
		err error
		ok  bool
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	assert.NotNil(ka)

	sa, err = c.NewState(ka)
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

	hb, err = c.DecryptHandshake(kb, box)
	assert.NoError(err)
	if assert.NotNil(hb) {
		assert.Equal(ka.Public(), hb.PublicKey().Public())
		assert.Equal(cipherset.Parts{0x01: "foobarzzzzfoobarzzzzfoobarzzzzfoobarzzzzfoobarzzzz34"}, hb.Parts())
		assert.Equal(uint32(1), hb.At())
	}

	sb, err = c.NewState(kb)
	assert.NoError(err)
	if assert.NotNil(sb) {
		assert.False(sb.CanEncryptMessage())
		assert.False(sb.CanEncryptHandshake())
		assert.False(sb.CanDecryptMessage())
		assert.True(sb.CanDecryptHandshake())
		assert.True(sb.NeedsRemoteKey())
	}

	if sb != nil && hb != nil {
		ok = sb.ApplyHandshake(hb)
		assert.True(ok)
		assert.True(sb.CanEncryptMessage())
		assert.True(sb.CanEncryptHandshake())
		assert.True(sb.CanDecryptMessage())
		assert.True(sb.CanDecryptHandshake())
		assert.False(sb.NeedsRemoteKey())
	}

	box, err = sb.EncryptHandshake(1, cipherset.Parts{0x01: "foobarzzzzfoobarzzzzfoobarzzzzfoobarzzzzfoobarzzzz34"})
	assert.NoError(err)
	assert.NotNil(box)

	ha, err = c.DecryptHandshake(ka, box)
	assert.NoError(err)
	assert.NotNil(ha)
	assert.Equal(kb.Public(), ha.PublicKey().Public())
	assert.Equal(cipherset.Parts{0x01: "foobarzzzzfoobarzzzzfoobarzzzzfoobarzzzzfoobarzzzz34"}, ha.Parts())
	assert.Equal(uint32(1), ha.At())

	ok = sa.ApplyHandshake(ha)
	assert.True(ok)
	assert.True(sa.CanEncryptMessage())
	assert.True(sa.CanEncryptHandshake())
	assert.True(sa.CanDecryptMessage())
	assert.True(sa.CanDecryptHandshake())
	assert.False(sa.NeedsRemoteKey())
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
		ha  cipherset.Handshake
		hb  cipherset.Handshake
		pkt *lob.Packet
		box []byte
		err error
		ok  bool
	)

	ka, err = c.GenerateKey()
	assert.NoError(err)
	kb, err = c.GenerateKey()
	assert.NoError(err)

	sa, err = c.NewState(ka)
	assert.NoError(err)
	sb, err = c.NewState(kb)
	assert.NoError(err)

	err = sa.SetRemoteKey(kb)
	assert.NoError(err)
	box, err = sa.EncryptHandshake(1, nil)
	assert.NoError(err)
	hb, err = c.DecryptHandshake(kb, box)
	assert.NoError(err)
	ok = sb.ApplyHandshake(hb)
	assert.True(ok)
	box, err = sb.EncryptHandshake(1, nil)
	assert.NoError(err)
	ha, err = c.DecryptHandshake(ka, box)
	assert.NoError(err)
	ok = sa.ApplyHandshake(ha)
	assert.True(ok)

	pkt = &lob.Packet{Body: []byte("Hello world!")}
	pkt.Header().SetInt("foo", 0xbeaf)
	pkt, err = sa.EncryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.True(pkt.Header().IsZero())
	assert.NotEmpty(pkt.Body)

	pkt, err = sb.DecryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Equal(&lob.Header{Extra: map[string]interface{}{"foo": 0xbeaf}}, pkt.Header())
	assert.Equal([]byte("Hello world!"), pkt.Body)

	pkt = &lob.Packet{Body: []byte("Bye world!")}
	pkt.Header().SetInt("bar", 0xdead)
	pkt, err = sb.EncryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.True(pkt.Header().IsZero())
	assert.NotEmpty(pkt.Body)

	pkt, err = sa.DecryptPacket(pkt)
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Nil(pkt.Head)
	assert.Equal(&lob.Header{Extra: map[string]interface{}{"bar": 0xdead}}, pkt.Header())
	assert.Equal([]byte("Bye world!"), pkt.Body)
}

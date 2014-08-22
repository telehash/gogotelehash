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
    compact map[string]string
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

  box, err = sa.EncryptHandshake(1, map[string]string{"01": "foobar"})
  assert.NoError(err)
  assert.NotNil(box)

  seq, kc, compact, err = sb.DecryptHandshake(box)
  assert.NoError(err)
  assert.NotNil(kc)
  assert.Equal(ka.Bytes(), kc.Bytes())
  assert.Equal(map[string]string{"01": "foobar"}, compact)
  assert.Equal(1, seq)
  assert.True(sb.CanEncryptMessage())
  assert.True(sb.CanEncryptHandshake())
  assert.True(sb.CanDecryptMessage())
  assert.True(sb.CanDecryptHandshake())
  assert.False(sb.NeedsRemoteKey())
}

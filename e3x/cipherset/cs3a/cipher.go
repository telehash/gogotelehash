// See:
// - https://github.com/telehash/telehash.org/blob/558332cd82dec3b619d194d42b3d16618f077e0f/v3/e3x/cipher_sets.md
// - https://github.com/telehash/telehash.org/blob/558332cd82dec3b619d194d42b3d16618f077e0f/v3/e3x/cs/3a.md
package cs3a

import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/binary"

  "code.google.com/p/go.crypto/nacl/box"
  "code.google.com/p/go.crypto/poly1305"

  "bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
  "bitbucket.org/simonmenke/go-telehash/lob"
)

var (
  _ cipherset.Cipher = (*cipher)(nil)
  _ cipherset.State  = (*state)(nil)
  _ cipherset.Key    = (*key)(nil)
)

type cipher struct{}

func (c *cipher) GenerateKey() (cipherset.Key, error) {
  return generateKey()
}

func (c *cipher) NewState(localKey cipherset.Key, isSender bool) (cipherset.State, error) {
  if k, ok := localKey.(*key); ok && k != nil && k.CanEncrypt() && k.CanSign() {
    s := &state{isSender: isSender, localKey: k}
    s.update()
    return s, nil
  }
  return nil, cipherset.ErrInvalidKey
}

type state struct {
  isSender      bool
  localKey      *key
  remoteKey     *key
  localLineKey  *key
  remoteLineKey *key
  macKeyBase    *[32]byte
  agreedKey     *[32]byte
}

func (s *state) SetRemoteKey(remoteKey cipherset.Key) error {
  if k, ok := remoteKey.(*key); ok && k != nil && k.CanEncrypt() {
    s.remoteKey = k
    s.update()
    return nil
  }
  return cipherset.ErrInvalidKey
}

func (s *state) setRemoteLineKey(k *key) {
  s.remoteLineKey = k
  s.update()
}

func (s *state) update() {
  // generate a local line Key
  if s.localLineKey == nil {
    s.localLineKey, _ = generateKey()
  }

  // generate mac key base
  if s.macKeyBase == nil && s.localKey.CanSign() && s.remoteKey.CanEncrypt() {
    s.macKeyBase = new([32]byte)
    box.Precompute(s.macKeyBase, s.remoteKey.pub, s.localKey.prv)
  }

  // generate agreed key
  if s.isSender && s.agreedKey == nil && s.localLineKey.CanSign() && s.remoteKey.CanEncrypt() {
    s.agreedKey = new([32]byte)
    box.Precompute(s.agreedKey, s.remoteKey.pub, s.localLineKey.prv)
  }

  if !s.isSender && s.agreedKey == nil && s.remoteLineKey.CanEncrypt() && s.localKey.CanSign() {
    s.agreedKey = new([32]byte)
    box.Precompute(s.agreedKey, s.remoteLineKey.pub, s.localKey.prv)
  }
}

func (s *state) macKey(seq []byte) *[32]byte {
  if len(seq) != 4 {
    return nil
  }

  if s.macKeyBase == nil {
    return nil
  }

  var (
    macKey = new([32]byte)
    sha    = sha256.New()
  )
  sha.Write(seq)
  sha.Write((*s.macKeyBase)[:])
  sha.Sum((*macKey)[:0])
  return macKey
}

func (s *state) sign(sig, seq, p []byte) {
  if len(sig) != 16 {
    panic("invalid sig buffer len(sig) must be 16")
  }

  var (
    sum [16]byte
    key = s.macKey(seq)
  )

  if key == nil {
    panic("unable to generate a signature")
  }

  poly1305.Sum(&sum, p, key)
  copy(sig, sum[:])
}

func (s *state) verify(sig, seq, p []byte) bool {
  if len(sig) != 16 {
    return false
  }

  var (
    sum [16]byte
    key = s.macKey(seq)
  )

  if key == nil {
    return false
  }

  copy(sum[:], sig)
  return poly1305.Verify(&sum, p, key)
}

func (s *state) NeedsRemoteKey() bool {
  return s.remoteKey == nil
}

func (s *state) CanEncryptMessage() bool {
  return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanEncryptHandshake() bool {
  return s.CanEncryptMessage()
}

func (s *state) CanDecryptMessage() bool {
  return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanDecryptHandshake() bool {
  return s.localKey != nil && s.localLineKey != nil
}

func (s *state) EncryptMessage(seq uint32, in []byte) ([]byte, error) {
  var (
    out   = make([]byte, 4+32+len(in)+box.Overhead+16)
    nonce [24]byte
    ctLen int
  )

  if !s.CanEncryptMessage() {
    panic("unable to encrypt message")
  }

  if seq == 0 {
    panic("cs3a: provided invalid seq")
  }

  // encode seq (into nonce)
  binary.BigEndian.PutUint32(nonce[:4], seq)
  copy(out[:4], nonce[:4])

  // copy public senderLineKey
  copy(out[4:4+32], (*s.localLineKey.pub)[:])

  // encrypt p
  ctLen = len(box.SealAfterPrecomputation(out[4+32:4+32], in, &nonce, s.agreedKey))

  // Sign message
  s.sign(out[4+32+ctLen:], nonce[:4], out[4:4+32+ctLen])

  return out[:4+32+ctLen+16], nil
}

func (s *state) DecryptMessage(p []byte) (uint32, []byte, error) {
  var (
    ctLen         = len(p) - (4 + 32 + 16)
    out           = make([]byte, ctLen)
    seq           uint32
    nonce         [24]byte
    remoteLineKey [32]byte
    ciphertext    []byte
    ok            bool
  )

  if !s.CanDecryptMessage() {
    return 0, nil, cipherset.ErrInvalidState
  }

  copy(nonce[:], p[:4])
  copy(remoteLineKey[:], p[4:4+32])
  ciphertext = p[4+32 : 4+32+ctLen]

  if !s.verify(p[4+32+ctLen:], p[:4], p[4:4+32+ctLen]) {
    return 0, nil, cipherset.ErrInvalidMessage
  }

  s.setRemoteLineKey(makeKey(nil, &remoteLineKey))

  // decode BODY
  out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, s.agreedKey)
  if !ok {
    return 0, nil, cipherset.ErrInvalidMessage
  }

  seq = binary.BigEndian.Uint32(nonce[:4])

  return seq, out, nil
}

func (s *state) EncryptHandshake(seq uint32, compact map[string]string) ([]byte, error) {
  data, err := lob.Encode(&lob.Packet{
    Json: compact,
    Body: s.localKey.Bytes(),
  })
  if err != nil {
    return nil, err
  }
  return s.EncryptMessage(seq, data)
}

func (s *state) DecryptHandshake(p []byte) (uint32, cipherset.Key, map[string]string, error) {
  var (
    ctLen         = len(p) - (4 + 32 + 16)
    out           = make([]byte, ctLen)
    seq           uint32
    nonce         [24]byte
    remoteKey     [32]byte
    remoteLineKey [32]byte
    ciphertext    []byte
    inner         *lob.Packet
    compact       map[string]string
    err           error
    ok            bool
  )

  if !s.CanDecryptHandshake() {
    return 0, nil, nil, cipherset.ErrInvalidState
  }

  copy(nonce[:], p[:4])
  copy(remoteLineKey[:], p[4:4+32])
  ciphertext = p[4+32 : 4+32+ctLen]

  s.setRemoteLineKey(makeKey(nil, &remoteLineKey))

  // decode BODY
  out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, s.agreedKey)
  if !ok {
    return 0, nil, nil, cipherset.ErrInvalidMessage
  }

  inner, err = lob.Decode(out)
  if err != nil {
    return 0, nil, nil, err
  }

  copy(remoteKey[:], inner.Body)
  s.SetRemoteKey(makeKey(nil, &remoteKey))

  if !s.CanDecryptMessage() {
    return 0, nil, nil, cipherset.ErrInvalidState
  }

  if !s.verify(p[4+32+ctLen:], p[:4], p[4:4+32+ctLen]) {
    return 0, nil, nil, cipherset.ErrInvalidMessage
  }

  if m, ok := inner.Json.(map[string]interface{}); ok && m != nil {
    compact = make(map[string]string, len(m))
    for k, v := range m {
      if s, ok := v.(string); ok && s != "" {
        compact[k] = s
      }
    }
  }

  seq = binary.BigEndian.Uint32(nonce[:4])

  return seq, s.remoteKey, compact, nil
}

type key struct {
  pub *[32]byte
  prv *[32]byte
}

func makeKey(prv, pub *[32]byte) *key {
  if prv != nil {
    prv_ := new([32]byte)
    copy((*prv_)[:], (*prv)[:])
    prv = prv_
  }

  if pub != nil {
    pub_ := new([32]byte)
    copy((*pub_)[:], (*pub)[:])
    pub = pub_
  }

  return &key{pub: pub, prv: prv}
}

func generateKey() (*key, error) {
  pub, prv, err := box.GenerateKey(rand.Reader)
  if err != nil {
    return nil, err
  }

  return makeKey(prv, pub), nil
}

func (k *key) Bytes() []byte {
  if k == nil || k.pub == nil {
    return nil
  }

  buf := make([]byte, 32)
  copy(buf, (*k.pub)[:])
  return buf
}

func (k *key) CanSign() bool {
  return k != nil && k.prv != nil
}

func (k *key) CanEncrypt() bool {
  return k != nil && k.pub != nil
}

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
)

var (
	_ cipherset.Cipher = (*cipher)(nil)
	// _ cipherset.Session = (*session)(nil)
	_ cipherset.Key = (*key)(nil)
)

type cipher struct{}

func (c *cipher) GenerateKey() (cipherset.Key, error) {
	return generateKey()
}

func (c *cipher) MessageOverhead() int {
	return 4 + 32 + box.Overhead + 16
}

func (c *cipher) EncryptMessage(receiverKey, senderKey, senderLineKey cipherset.Key, seq uint32, in, out []byte) ([]byte, error) {
	var (
		nonce          [24]byte
		agreedKey      [32]byte
		senderKey_     *key
		receiverKey_   *key
		senderLineKey_ *key
		ctLen          int
		err            error
	)

	if maxLen := len(in) + c.MessageOverhead(); len(out) < maxLen {
		if cap(out) < maxLen {
			return nil, cipherset.ErrNotEnoughBufferSpace
		} else {
			out = out[:maxLen]
		}
	}

	if k, ok := senderKey.(*key); ok && k != nil {
		senderKey_ = k
	} else {
		panic("cs3a: provided invalid senderKey")
	}

	if k, ok := receiverKey.(*key); ok && k != nil {
		receiverKey_ = k
	} else {
		panic("cs3a: provided invalid receiverKey")
	}

	if seq == 0 {
		panic("cs3a: provided invalid seq")
	}

	if senderLineKey != nil {
		if k, ok := senderLineKey.(*key); ok && k != nil {
			senderLineKey_ = k
		} else {
			panic("cs3a: provided invalid senderLineKey")
		}
	}

	// Generate a new line key-pair when none was given
	if senderLineKey_ == nil {
		senderLineKey_, err = generateKey()
		if err != nil {
			return nil, err
		}
	}

	// encode seq (into nonce)
	binary.BigEndian.PutUint32(nonce[:4], seq)
	copy(out[:4], nonce[:4])

	// copy public senderLineKey
	copy(out[4:4+32], (*senderLineKey_.pub)[:])

	// make agreedKey
	box.Precompute(&agreedKey, receiverKey_.pub, senderLineKey_.prv)

	// encrypt p
	ctLen = len(box.SealAfterPrecomputation(out[4+32:4+32], in, &nonce, &agreedKey))

	// Sign message
	sign_data(
		out[4+32+ctLen:],
		receiverKey_,
		senderKey_,
		nonce[:4],
		out[4:4+32+ctLen],
	)

	return out[:4+32+ctLen+16], nil
}

func (c *cipher) DecryptMessage(receiverKey, senderKey cipherset.Key, p []byte) (uint32, []byte, error) {
	var (
		ctLen         = len(p) - (4 + 32 + 16)
		out           = make([]byte, ctLen)
		seq           uint32
		nonce         [24]byte
		senderLineKey [32]byte
		agreedKey     [32]byte
		mac           [16]byte
		macKey        [32]byte
		macData       []byte
		ciphertext    []byte
		senderKey_    *key
		receiverKey_  *key
		ok            bool
	)

	copy(nonce[:], p[:4])
	copy(senderLineKey[:], p[4:4+32])
	copy(mac[:], p[4+32+ctLen:])
	macData = p[4 : 4+32+ctLen]
	ciphertext = p[4+32 : 4+32+ctLen]

	if senderKey != nil {
		if k, ok := senderKey.(*key); ok {
			senderKey_ = k
		} else {
			panic("cs3a: provided invalid senderKey")
		}
	}

	if k, ok := receiverKey.(*key); ok && k != nil {
		receiverKey_ = k
	} else {
		panic("cs3a: provided invalid receiverKey")
	}

	{ // # VERIFY MAC
		// make macKey
		box.Precompute(&macKey, senderKey_.pub, receiverKey_.prv)
		sha := sha256.New()
		sha.Write(nonce[:4])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])

		// verify mac
		if !poly1305.Verify(&mac, macData, &macKey) {
			return 0, nil, cipherset.ErrInvalidMac
		}
	}

	{ // # DECRYPT INNER
		// make agreedKey
		box.Precompute(&agreedKey, &senderLineKey, receiverKey_.prv)

		// decode BODY
		out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, &agreedKey)
		if !ok {
			return 0, nil, cipherset.ErrInvalidBody
		}
	}

	seq = binary.BigEndian.Uint32(nonce[:4])

	return seq, out, nil
}

func (c *cipher) EncryptHandshake(receiverKey, senderKey, senderLineKey cipherset.Key, seq uint32, out []byte) ([]byte, error) {
	return c.EncryptMessage(receiverKey, senderKey, senderLineKey, seq, senderKey.Bytes(), out)
}

func (c *cipher) DecryptHandshake(receiverKey cipherset.Key, p []byte) (uint32, cipherset.Key, error) {
	var (
		ctLen         = len(p) - (4 + 32 + 16)
		seq           uint32
		nonce         [24]byte
		senderLineKey [32]byte
		agreedKey     [32]byte
		mac           [16]byte
		macKey        [32]byte
		macData       []byte
		ciphertext    []byte
		senderKey_    *key
		receiverKey_  *key
		ok            bool
	)

	copy(nonce[:], p[:4])
	copy(senderLineKey[:], p[4:4+32])
	copy(mac[:], p[4+32+ctLen:])
	macData = p[4 : 4+32+ctLen]
	ciphertext = p[4+32 : 4+32+ctLen]

	if k, ok := receiverKey.(*key); ok && k != nil {
		receiverKey_ = k
	} else {
		panic("cs3a: provided invalid receiverKey")
	}

	{ // # DECRYPT INNER
		senderKey_ = &key{}
		senderKey_.pub = new([32]byte)

		// make agreedKey
		box.Precompute(&agreedKey, &senderLineKey, receiverKey_.prv)

		// decode BODY
		_, ok = box.OpenAfterPrecomputation((*senderKey_.pub)[:0], ciphertext, &nonce, &agreedKey)
		if !ok {
			return 0, nil, cipherset.ErrInvalidBody
		}
	}

	{ // # VERIFY MAC
		// make macKey
		box.Precompute(&macKey, senderKey_.pub, receiverKey_.prv)
		sha := sha256.New()
		sha.Write(nonce[:4])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])

		// verify mac
		if !poly1305.Verify(&mac, macData, &macKey) {
			return 0, nil, cipherset.ErrInvalidMac
		}
	}

	seq = binary.BigEndian.Uint32(nonce[:4])

	return seq, senderKey_, nil
}

func sign_data(out []byte, receiverKey, senderKey *key, seq, data []byte) {
	var (
		macKey [32]byte
		mac    [16]byte
	)

	// make macKey
	box.Precompute(&macKey, receiverKey.pub, senderKey.prv)
	sha := sha256.New()
	sha.Write(seq)
	sha.Write(macKey[:])
	sha.Sum(macKey[:0])

	// make mac
	poly1305.Sum(&mac, data, &macKey)
	copy(out, mac[:])
}

func (c *cipher) MakeSession(localKey, remoteKey cipherset.Key) (cipherset.Session, error) {
	panic("not implemented")
}

type state struct {
	localKey      *key
	remoteKey     *key
	localLineKey  *key
	remoteLineKey *key
	macKeyBase    *[32]byte
	agreedKey     *[32]byte
}

func (s *state) SetRemoteKey(k *key) {
	s.remoteKey = k
	s.update()
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
	if s.agreedKey == nil && s.localLineKey.CanSign() && s.remoteKey.CanEncrypt() {
		s.agreedKey = new([32]byte)
		box.Precompute(s.agreedKey, s.remoteKey.pub, s.localLineKey.prv)
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

func (s *state) NeedsHandshake() bool {
	return s.remoteKey == nil
}

func (s *state) CanEncryptMessage() bool {
	return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanEncryptHandshake() bool {
	return s.CanEncryptMessage()
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

	copy(nonce[:], p[:4])
	copy(remoteLineKey[:], p[4:4+32])
	ciphertext = p[4+32 : 4+32+ctLen]

	if !s.verify(p[4+32+ctLen:], p[:4], p[4:4+32+ctLen]) {
		return 0, nil, cipherset.ErrInvalidMac
	}

	s.setRemoteLineKey(makeKey(nil, &remoteLineKey))

	// decode BODY
	out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, s.agreedKey)
	if !ok {
		return 0, nil, cipherset.ErrInvalidBody
	}

	seq = binary.BigEndian.Uint32(nonce[:4])

	return seq, out, nil
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

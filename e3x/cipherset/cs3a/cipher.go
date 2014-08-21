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

	"github.com/fd/th/e3x/cipherset"
)

var (
	_ cipherset.Cipher = (*cipher)(nil)
	// _ cipherset.Session = (*session)(nil)
	_ cipherset.Key = (*key)(nil)
)

type cipher struct{}

func (c *cipher) GenerateKey() (cipherset.Key, error) {
	return c.generateKey()
}

func (c *cipher) generateKey() (*key, error) {
	pub, prv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &key{pub: pub, prv: prv}, nil
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
		senderLineKey_, err = c.generateKey()
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

type key struct {
	pub *[32]byte
	prv *[32]byte
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

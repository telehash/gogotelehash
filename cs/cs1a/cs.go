package cs1a

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/gokyle/ecdh"
)

type CipherSet struct {
	prv_key     []byte // 20 bytes
	pub_key     []byte // 40 bytes
	key         *ecdh.PrivateKey
	fingerprint string
}

type lineCipher struct {
	cipher_set *CipherSet
	local      struct {
		line_key_prv []byte
		line_key_pub []byte
	}
	remote struct {
		hashname_key []byte
		line_key     []byte
	}
}

func New(prv_key, pub_key []byte) *CipherSet {
	cs := &CipherSet{}

	if len(prv_key) != 20 {
		panic("Invalid secp160r1 private key")
	}
	if len(pub_key) != 40 {
		panic("Invalid secp160r1 public key")
	}

	cs.prv_key = prv_key
	cs.pub_key = pub_key
	cs.key = unmarshal_prv_key(p160, cs.prv_key, cs.pub_key)

	{
		b := sha1.Sum(pub_key)
		cs.fingerprint = hex.EncodeToString(b)
	}
}

func (cs *CipherSet) Fingerprint() string {
	return cs.fingerprint
}

func (cs *CipherSet) NewCipher(rand io.Reader) (Cipher, error) {
	prv, pub, err := GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	cipher := &lineCipher{}
	cipher.cipher_set = cs
	cipher.local.line_key_prv = prv
	cipher.local.line_key_pub = pub
	return cipher, nil
}

func (cs *lineCipher) HandleOpen(body []byte) error {
	if len(body) < 60 {
		return &InvalidPacketError{}
	}

	line_key_data := body[20:60]

	line_key := unmarshal_pub_key(p160, line_key_data)
	if line_key == nil {
		return &InvalidPacketError{}
	}

	sk, err := cs.key.GenerateShared(line_key, 20)
	if err != nil {
		return &InvalidPacketError{err}
	}

	hashname_key_data, err := dec_AES_128_CTR(sk, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, body[60:])
	if err != nil {
		return &InvalidPacketError{err}
	}
	if len(hashname_key_data) != 40 {
		return &InvalidPacketError{}
	}

	hashname_key := unmarshal_pub_key(p160, hashname_key_data)
	if hashname_key == nil {
		return &InvalidPacketError{}
	}

	sk, err = cs.cipher_set.key.GenerateShared(hashname_key, 20)
	if err != nil {
		return &InvalidPacketError{err}
	}

	mac := hmac.New(sha1.New, sk)
	mac.Write(body[20:])
	if !hmac.Equal(mac.Sum(nil), body[:20]) {
		return &InvalidPacketError{}
	}

	cs.remote.hashname_key = hashname_key_data
	cs.remote.line_key = line_key_data
	return nil
}

func unmarshal_pub_key(curve elliptic.Curve, data []byte) *ecdh.PublicKey {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != 2*byteLen {
		return
	}
	x := new(big.Int).SetBytes(data[:byteLen])
	y := new(big.Int).SetBytes(data[byteLen:])
	return &ecdh.PublicKey{x, y, curve}
}

func unmarshal_prv_key(curve elliptic.Curve, prv, pub []byte) *ecdh.PrivateKey {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(prv) != byteLen {
		return
	}
	if len(pub) != 2*byteLen {
		return
	}
	d := new(big.Int).SetBytes(prv)
	x := new(big.Int).SetBytes(pub[:byteLen])
	y := new(big.Int).SetBytes(pub[byteLen:])
	return &ecdh.PrivateKey{ecdh.PublicKey{x, y, curve}, d}
}

func dec_AES_128_CTR(key, iv, data []byte) ([]byte, error) {
	var (
		err        error
		buf_data   = make([]byte, 0, 1500)
		buf        = bytes.NewBuffer(buf_data)
		aes_blk    cipher.Block
		aes_stream cipher.Stream
		aes_r      *cipher.StreamReader
	)

	aes_blk, err = aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	aes_stream = cipher.NewCTR(aes_blk, iv)
	aes_r = &cipher.StreamReader{S: aes_stream, R: bytes.NewReader(data)}

	_, err = io.Copy(buf, aes_r)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func enc_AES_128_CTR(key, iv, data []byte) ([]byte, error) {
	var (
		err        error
		buf_data   = make([]byte, 0, 1500)
		buf        = bytes.NewBuffer(buf_data)
		aes_blk    cipher.Block
		aes_stream cipher.Stream
		aes_w      *cipher.StreamWriter
	)

	aes_blk, err = aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	aes_stream = cipher.NewCTR(aes_blk, iv)
	aes_w = &cipher.StreamWriter{S: aes_stream, W: buf}

	_, err = aes_w.Write(data)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

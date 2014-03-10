// Rev: 17d1b31df9a01f7b5b86932300da2c2e21d5e764

package cs1a

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
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
	enc_key    []byte
	dec_key    []byte
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

func (cs *CipherSet) NewCipher(rand io.Reader, hashname_key []byte) (Cipher, error) {
	prv, pub, err := GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	if l := len(hashname_key); l != 40 && l != 0 {
		return nil, errors.New("cs1a: Invalid hashname key")
	} else if l == 0 {
		hashname_key = nil
	}

	cipher := &lineCipher{}
	cipher.cipher_set = cs
	cipher.local.line_key_prv = prv
	cipher.local.line_key_pub = pub
	cipher.remote.hashname_key = hashname_key
	return cipher, nil
}

func (cs *lineCipher) DecodeOpen(body []byte) error {
	// validate open packet
	if len(body) < 60 {
		return &InvalidPacketError{}
	}

	line_key_data := body[20:60]

	line_key := unmarshal_pub_key(p160, line_key_data)
	if line_key == nil {
		return &InvalidPacketError{}
	}

	sk, err := cs.cipher_set.key.GenerateShared(line_key, 20)
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

	// generate line keys
	line_prv_key := unmarshal_prv_key(p160, cs.local.line_key_prv, cs.local.line_key_pub)
	if line_prv_key == nil {
		return &InvalidPacketError{}
	}

	sk, err = line_prv_key.GenerateShared(line_key, 20)
	if err != nil {
		return &InvalidPacketError{err}
	}

	sha := sha1.New()
	sha.Write(sk)
	sha.Write(cs.local.line_key_pub)
	sha.Write(line_key_data)
	cs.enc_key = sha.Sum(nil)[:16]

	sha.Reset()
	sha.Write(sk)
	sha.Write(line_key_data)
	sha.Write(cs.local.line_key_pub)
	cs.dec_key = sha.Sum(nil)[:16]

	cs.remote.hashname_key = hashname_key_data
	cs.remote.line_key = line_key_data
	return nil
}

func (cs *lineCipher) EncodeOpen() ([]byte, error) {
	if cs.remote.hashname_key == nil {
		return nil, &EncodePacketError{}
	}

	line_prv_key := unmarshal_prv_key(p160, cs.local.line_key_prv, cs.local.line_key_pub)
	if line_prv_key == nil {
		return nil, &EncodePacketError{}
	}

	hashname_key := unmarshal_pub_key(p160, cs.remote.hashname_key)
	if hashname_key == nil {
		return nil, &EncodePacketError{}
	}

	sk, err := line_prv_key.GenerateShared(hashname_key, 20)
	if err != nil {
		return nil, &EncodePacketError{err}
	}

	outer := make([]byte, 60+40)
	err = enc_AES_128_CTR(outer[60:], sk, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, cs.cipher_set.pub_key)
	if err != nil {
		return nil, &EncodePacketError{err}
	}

	copy(outer[20:60], cs.local.line_key_pub)

	sk, err = cs.cipher_set.key.GenerateShared(hashname_key, 20)
	if err != nil {
		return nil, &EncodePacketError{err}
	}

	mac := hmac.New(sha1.New, sk)
	mac.Write(outer[20:])
	copy(outer[:20], mac.Sum(nil))

	return outer, nil
}

func (cs *lineCipher) DecodeLine(body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, &InvalidPacketError{}
	}

	mac := hmac.New(sha1.New, cs.dec_key)
	mac.Write(body[4:])
	if !bytes.Equal(mac.Sum(nil)[4:], body[:4]) {
		return nil, &InvalidPacketError{}
	}

	// empty body
	if len(body) == 8 {
		return nil, nil
	}

	iv := make([]byte, 16)
	copy(iv, body[4:8])

	inner, err := dec_AES_128_CTR(cs.dec_key, iv, body[8:])
	if err != nil {
		return nil, &InvalidPacketError{err}
	}

	return inner, nil
}

func (cs *lineCipher) EncodeLine(body []byte) ([]byte, error) {
	outer := make([]byte, 8+body)

	_, err := io.ReadFull(rand.Reader, outer[4:8])
	if err != nil {
		return nil, &EncodePacketError{err}
	}

	err = enc_AES_128_CTR(outer[8:], cs.enc_key, outer[4:8], body)
	if err != nil {
		return nil, &EncodePacketError{err}
	}

	mac := hmac.New(sha1.New, cs.enc_key)
	mac.Write(outer[4:])
	copy(outer[:4], mac.Sum(nil)[:4])

	return outer, nil
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

func enc_AES_128_CTR(out, key, iv, data []byte) error {
	var (
		err        error
		buf        = bytes.NewBuffer(out[:0])
		aes_blk    cipher.Block
		aes_stream cipher.Stream
		aes_w      *cipher.StreamWriter
	)

	aes_blk, err = aes.NewCipher(key[:16])
	if err != nil {
		return err
	}

	aes_stream = cipher.NewCTR(aes_blk, iv)
	aes_w = &cipher.StreamWriter{S: aes_stream, W: buf}

	_, err = aes_w.Write(data)
	if err != nil {
		return err
	}

	return nil
}

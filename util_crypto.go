package telehash

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
)

func make_rand(n int) ([]byte, error) {
	b := make([]byte, n)
	w := b

	for len(w) != 0 {
		r, err := rand.Read(w)
		if err != nil {
			return nil, err
		}
		w = w[r:]
	}

	return b, nil
}

func make_hex_rand(n int) (string, error) {
	buf, err := make_rand(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func hash_SHA256(data ...[]byte) []byte {
	h := sha256.New()
	for _, c := range data {
		h.Write(c)
	}
	return h.Sum(nil)
}

func dec_AES_256_CTR(key, iv, data []byte) ([]byte, error) {
	var (
		err        error
		buf_data   = make([]byte, 0, 1500)
		buf        = bytes.NewBuffer(buf_data)
		aes_blk    cipher.Block
		aes_stream cipher.Stream
		aes_r      *cipher.StreamReader
	)

	aes_blk, err = aes.NewCipher(key)
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

func enc_AES_256_CTR(key, iv, data []byte) ([]byte, error) {
	var (
		err        error
		buf_data   = make([]byte, 0, 1500)
		buf        = bytes.NewBuffer(buf_data)
		aes_blk    cipher.Block
		aes_stream cipher.Stream
		aes_w      *cipher.StreamWriter
	)

	aes_blk, err = aes.NewCipher(key)
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

func enc_DER_RSA(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func dec_DER_RSA(der []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok || key == nil {
		return nil, fmt.Errorf("telehash: not an RSA key")
	}
	if pub.N.Sign() <= 0 {
		return nil, fmt.Errorf("telehash: RSA modulus is not a positive number")
	}
	if pub.E <= 0 {
		return nil, fmt.Errorf("telehash: RSA public exponent is not a positive number")
	}
	return pub, nil
}

package telehash

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
)

func make_rand(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
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

func hashname_from_RSA(pub *rsa.PublicKey) (string, error) {
	der, err := enc_DER_RSA(pub)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash_SHA256(der)), nil
}

func enc_DER_RSA(pub *rsa.PublicKey) ([]byte, error) {
	return asn1.Marshal(*pub)
}

func dec_DER_RSA(der []byte) (*rsa.PublicKey, error) {
	pub := &rsa.PublicKey{}
	_, err := asn1.Unmarshal(der, pub)
	if err != nil {
		return nil, err
	}
	if pub.N.Sign() <= 0 {
		return nil, fmt.Errorf("telehash: RSA modulus is not a positive number")
	}
	if pub.E <= 0 {
		return nil, fmt.Errorf("telehash: RSA public exponent is not a positive number")
	}
	return pub, nil
}

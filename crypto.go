package telehash

import "crypto/rsa"
import "crypto/sha1"
import "crypto/sha256"
import "crypto/rand"
import "github.com/gokyle/ecdh"


func EncryptWithRSA(pub *rsa.PublicKey, cleartext []byte) (ciphertext []byte, err error) {
	// Use RSA-OEAP w/ SHA1 as hash and no value for the label
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, cleartext, nil)
}

func DecryptWithRSA(priv *rsa.PrivateKey, ciphertext []byte) (cleartext []byte, err error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

func SignWithRSA(priv *rsa.PrivateKey, data []byte) (sig []byte, err error) {
	// Sign the SHA-256 hash using PKCS1v15 (RSA PKCS#1 v1.5)
	return rsa.SignPKCS1v15(rand.Reader, priv, sha256.New(), sha256Hash(data))
}

func IsSignatureValid(pub *rsa.PublicKey, data []byte, sig []byte) bool {
	err := rsa.VerifyPKCS1v15(pub, sha256.New(), sha256Hash(data), sig)
	return err == nil
}

func GenerateFingerprint(pub *ecdh.PublicKey) []byte {
	// Construct a SHA-256 fingerprint of the ECC public key. The key should
	// be marshalled into uncompressed point form, per 4.3.6, ANSI X.9.62
	return sha256(elliptic.Marshal(pub.Curve, pub.X, pub.Y))
}

func GenerateSharedKey(pub *ecdh.PublicKey) (key []byte, err error) {
}


func sha256Hash(data []byte) []byte {
	h := sha256.New()
	io.Write(h, data)
	return h.Sum(nil)
}

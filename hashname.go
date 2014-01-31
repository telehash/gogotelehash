package telehash

import (
	"crypto/rsa"
	"encoding/hex"
)

var ZeroHashname Hashname

const hashname_len = 32

type Hashname [hashname_len]byte

func HashnameFromPublicKey(pubkey *rsa.PublicKey) (Hashname, error) {
	der, err := enc_DER_RSA(pubkey)
	if err != nil {
		return ZeroHashname, err
	}

	return HashnameFromBytes(hash_SHA256(der))
}

func HashnameFromString(s string) (Hashname, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return ZeroHashname, ErrInvalidHashname
	}

	return HashnameFromBytes(b)
}

func HashnameFromBytes(b []byte) (Hashname, error) {
	if len(b) != hashname_len {
		return ZeroHashname, ErrInvalidHashname
	}

	h := Hashname{}
	copy(h[:], b)

	return h, nil
}

func (h Hashname) String() string {
	return hex.EncodeToString(h[:])
}

func (h Hashname) Short() string {
	return h.String()[:8]
}

func (h Hashname) Bytes() []byte {
	return h[:]
}

func (h Hashname) IsZero() bool {
	return h == ZeroHashname
}

func HashnamePrefix(a, b Hashname) string {
	for i, byte_a := range a {
		byte_b := b[i]

		if byte_a != byte_b && i < hashname_len-1 {
			return hex.EncodeToString(b[:i+1])
		}
	}

	return hex.EncodeToString(b[:])
}

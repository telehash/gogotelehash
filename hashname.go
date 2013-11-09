package telehash

import (
	"crypto/rsa"
	"encoding/hex"
)

var ZeroHashname Hashname

type Hashname [32]byte

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
	if len(b) != 32 {
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

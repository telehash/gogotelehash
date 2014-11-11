// Package hashname provides the Hashname type and its derivation functions.
//
// See: https://github.com/telehash/telehash.org/tree/558332cd82dec3b619d194d42b3d16618f077e0f/v3/hashname
package hashname

import (
	"crypto/sha256"
	"errors"
	"sort"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/util/base32util"
)

// ErrNoIntermediateParts is returned when deriving a Hashname
var ErrNoIntermediateParts = errors.New("hashname: no intermediate parts")

// ErrInvalidIntermediatePart is returned when deriving a Hashname
var ErrInvalidIntermediatePart = errors.New("hashname: invalid intermediate part")

// ErrInvalidIntermediatePartID is returned when deriving a Hashname
var ErrInvalidIntermediatePartID = errors.New("hashname: invalid intermediate part id")

// ErrInvalidKey is returned when deriving a Hashname
var ErrInvalidKey = errors.New("hashname: invalid key")

// H represents a hashname.
type H string

// Valid returns true when h is a valid hashname. A hashname must match [a-z2-7]{52}.
func (h H) Valid() bool {
	if len(h) != 52 {
		return false
	}

	return base32util.ValidString(string(h))
}

// FromIntermediates derives a hashname from its intermediate parts.
func FromIntermediates(parts cipherset.Parts) (H, error) {
	if len(parts) == 0 {
		return "", ErrNoIntermediateParts
	}

	var (
		hash = sha256.New()
		ids  = make([]int, 0, len(parts))
		buf  [32]byte
	)

	for id := range parts {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	for _, id := range ids {

		// decode intermediate part
		partString := parts[uint8(id)]
		if len(partString) != 52 {
			return "", ErrInvalidIntermediatePart
		}
		part, err := base32util.DecodeString(partString)
		if err != nil {
			return "", ErrInvalidIntermediatePart
		}

		buf[0] = byte(id)
		hash.Write(buf[:1])
		hash.Sum(buf[:0])
		hash.Reset()

		hash.Write(buf[:32])
		hash.Write(part)
		hash.Sum(buf[:0])
		hash.Reset()

		hash.Write(buf[:32])
	}

	return H(base32util.EncodeToString(buf[:32])), nil
}

// FromKeys derives a hashname from its public keys.
func FromKeys(keys cipherset.Keys) (H, error) {
	var (
		hash          = sha256.New()
		intermediates = make(cipherset.Parts, len(keys))
		buf           [32]byte
	)

	for id, key := range keys {
		hash.Write(key.Public())
		hash.Sum(buf[:0])
		hash.Reset()

		intermediates[id] = base32util.EncodeToString(buf[:])[:52]
	}

	return FromIntermediates(intermediates)
}

// PartsFromKeys derives the intermediate parts from their respectve public keys.
func PartsFromKeys(keys cipherset.Keys) cipherset.Parts {
	var (
		hash          = sha256.New()
		intermediates = make(cipherset.Parts, len(keys))
		buf           [32]byte
	)

	for id, key := range keys {
		hash.Write(key.Public())
		hash.Sum(buf[:0])
		hash.Reset()

		intermediates[id] = base32util.EncodeToString(buf[:])[:52]
	}

	return intermediates
}

// FromKeyAndIntermediates derives a hasname from a public key and some intermediate parts.
func FromKeyAndIntermediates(id uint8, key []byte, intermediates cipherset.Parts) (H, error) {
	var (
		all          = make(cipherset.Parts, len(intermediates)+1)
		sum          = sha256.Sum256(key)
		intermediate = base32util.EncodeToString(sum[:])
	)

	for k, v := range intermediates {
		all[k] = v
	}
	all[id] = intermediate

	return FromIntermediates(all)
}

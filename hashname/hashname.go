// See: https://github.com/telehash/telehash.org/tree/558332cd82dec3b619d194d42b3d16618f077e0f/v3/hashname
package hashname

import (
	"crypto/sha256"
	"errors"
	"sort"

	"bitbucket.org/simonmenke/go-telehash/base32"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
)

var ErrNoIntermediateParts = errors.New("hashname: no intermediate parts")
var ErrInvalidIntermediatePart = errors.New("hashname: invalid intermediate part")
var ErrInvalidIntermediatePartId = errors.New("hashname: invalid intermediate part id")
var ErrInvalidKey = errors.New("hashname: invalid key")

type H string

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
		part, err := base32.DecodeString(partString)
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

	return H(base32.EncodeToString(buf[:32])), nil
}

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

		intermediates[id] = base32.EncodeToString(buf[:])[:52]
	}

	return FromIntermediates(intermediates)
}

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

		intermediates[id] = base32.EncodeToString(buf[:])[:52]
	}

	return intermediates
}

func FromKeyAndIntermediates(id uint8, key []byte, intermediates cipherset.Parts) (H, error) {
	var (
		all          = make(cipherset.Parts, len(intermediates)+1)
		sum          = sha256.Sum256(key)
		intermediate = base32.EncodeToString(sum[:])
	)

	for k, v := range intermediates {
		all[k] = v
	}
	all[id] = intermediate

	return FromIntermediates(all)
}

func (h H) Less(b H) bool {
	return h < b
}

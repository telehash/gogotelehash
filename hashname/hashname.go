// See: https://github.com/telehash/telehash.org/tree/558332cd82dec3b619d194d42b3d16618f077e0f/v3/hashname
package hashname

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"sort"
)

var ErrNoIntermediateParts = errors.New("hashname: no intermediate parts")
var ErrInvalidIntermediatePart = errors.New("hashname: invalid intermediate part")
var ErrInvalidIntermediatePartId = errors.New("hashname: invalid intermediate part id")
var ErrInvalidKey = errors.New("hashname: invalid key")
var base32Enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

type H string

func FromIntermediates(parts map[string]string) (H, error) {
	if len(parts) == 0 {
		return "", ErrNoIntermediateParts
	}

	var (
		hash = sha256.New()
		ids  = make([]string, 0, len(parts))
		buf  [32]byte
	)

	for id := range parts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, idString := range ids {

		// decode intermediate part id
		if len(idString) != 2 {
			return "", ErrInvalidIntermediatePartId
		}
		id, err := hex.DecodeString(idString)
		if err != nil {
			return "", ErrInvalidIntermediatePart
		}

		// decode intermediate part
		partString := parts[idString]
		if len(partString) != 52 {
			return "", ErrInvalidIntermediatePart
		}
		part, err := base32Enc.DecodeString(partString + "====")
		if err != nil {
			return "", ErrInvalidIntermediatePart
		}

		hash.Write(id)
		hash.Sum(buf[:0])
		hash.Reset()

		hash.Write(buf[:32])
		hash.Write(part)
		hash.Sum(buf[:0])
		hash.Reset()

		hash.Write(buf[:32])
	}

	return H(base32Enc.EncodeToString(buf[:32])[:52]), nil
}

func FromKeys(keys map[string]string) (H, error) {
	var (
		hash          = sha256.New()
		intermediates = make(map[string]string, len(keys))
		buf           [32]byte
	)

	for id, keyString := range keys {
		key, err := base32Enc.DecodeString(keyString)
		if err != nil {
			return "", ErrInvalidKey
		}
		if len(key) == 0 {
			return "", ErrInvalidKey
		}

		hash.Write(key)
		hash.Sum(buf[:0])
		hash.Reset()

		intermediates[id] = base32Enc.EncodeToString(buf[:])[:52]
	}

	return FromIntermediates(intermediates)
}

func FromKeyAndIntermediates(id string, key []byte, intermediates map[string]string) (H, error) {
	var (
		all          = make(map[string]string, len(intermediates)+1)
		sum          = sha256.Sum256(key)
		intermediate = base32Enc.EncodeToString(sum[:])
	)

	for k, v := range intermediates {
		all[k] = v
	}
	all[id] = intermediate

	return FromIntermediates(all)
}

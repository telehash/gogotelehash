package kademlia

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/util/base32util"
)

const KeyLen = 32

type Key [KeyLen]byte
type keyDist [KeyLen]byte

func KeyFromHashname(h hashname.H) (Key, error) {
	if !h.Valid() {
		return Key{}, errors.New("invalid hashname")
	}

	data, err := base32util.DecodeString(string(h))
	if err != nil {
		return Key{}, errors.New("invalid hashname")
	}

	var k Key
	copy(k[:], data)
	return k, nil
}

func KeyFromBytes(b []byte) Key {
	return Key(sha256.Sum256(b))
}

func KeyFromString(s string) Key {
	return KeyFromBytes([]byte(s))
}

func distance(a, b hashname.H) keyDist {
	var (
		bData []byte
		err   error
	)

	bData, err = base32util.DecodeString(string(b))
	if err != nil {
		return keyDist{}
	}

	return keyDistance(a, bData)
}

func keyDistance(a hashname.H, bData []byte) keyDist {
	var (
		aData []byte
		err   error
		d     keyDist
	)

	aData, err = base32util.DecodeString(string(a))
	if err != nil {
		return d
	}

	if len(aData) != len(bData) {
		return d
	}

	if len(aData) != KeyLen {
		return d
	}

	for i, x := range aData {
		d[i] = x ^ bData[i]
	}

	return d
}

func bucketFromDistance(distance keyDist) int {
	var (
		b = 0
		x byte
	)

	for _, x = range distance {
		if x > 0 {
			break
		}
		b += 8
	}

	if b == numBuckets {
		return -1
	}

	switch {
	case (x >> 7) > 0: // 1xxx xxxx
		b += 0
	case (x >> 6) > 0: // 01xx xxxx
		b += 1
	case (x >> 5) > 0: // 001x xxxx
		b += 2
	case (x >> 4) > 0: // 0001 xxxx
		b += 3
	case (x >> 3) > 0: // 0000 1xxx
		b += 4
	case (x >> 2) > 0: // 0000 01xx
		b += 5
	case (x >> 1) > 0: // 0000 001x
		b += 6
	default: // 0000 0001
		b += 7
	}

	return b
}

func distanceLess(a, b keyDist) bool {
	return bytes.Compare(a[:], b[:]) < 0
}

func distanceLessOrEqual(a, b keyDist) bool {
	return bytes.Compare(a[:], b[:]) <= 0
}

// Package hashname provides the Hashname type and its derivation functions.
//
// See: https://github.com/telehash/telehash.org/tree/558332cd82dec3b619d194d42b3d16618f077e0f/v3/hashname
package hashname

import (
	"errors"

	"github.com/telehash/gogotelehash/internal/util/base32util"
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

func (h H) Network() string {
	return "telehash"
}

func (h H) String() string {
	return string(h)
}

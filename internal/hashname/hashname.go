// Package hashname provides the Hashname type and its derivation functions.
//
// See: https://github.com/telehash/telehash.org/tree/558332cd82dec3b619d194d42b3d16618f077e0f/v3/hashname
package hashname

import (
	"github.com/telehash/gogotelehash/internal/util/base32util"
)

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

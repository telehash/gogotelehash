package e3x

import (
	"github.com/telehash/gogotelehash/hashname"
)

// Identifier represents an identifing set of information which can be resolved
// into a full Identity.
type Identifier interface {
	Hashname() hashname.H
	String() string

	Identify(endpoint *Endpoint) (*Identity, error)
}

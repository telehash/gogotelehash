package e3x

import (
	"errors"

	"github.com/telehash/gogotelehash/internal/hashname"
)

var ErrUnidentifiable = errors.New("unidentifiable identity")

// Identifier represents an identifing set of information which can be resolved
// into a full Identity.
type Identifier interface {
	String() string

	Identify(endpoint *Endpoint) (*Identity, error)
}

type hashnameIdentifier hashname.H

// HashnameIdentifier returns an identifer which identifies an Identity using only
// information internal to an endpoint. In other words it will return the Identity
// associated with a hashname if that information is available within the endpoint.
func HashnameIdentifier(hn hashname.H) Identifier {
	return hashnameIdentifier(hn)
}

func (i hashnameIdentifier) String() string { return string(i) }
func (i hashnameIdentifier) Identify(endpoint *Endpoint) (*Identity, error) {
	x := endpoint.hashnames[hashname.H(i)]
	if x == nil {
		return nil, ErrUnidentifiable
	}

	return x.RemoteIdentity(), nil
}

package peers

import (
	"fmt"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/hashname"
)

var (
	_ e3x.Identifier = (*identifier)(nil)
)

func Via(router, target hashname.H) e3x.Identifier {
	return &identifier{target, router}
}

type identifier struct {
	hn     hashname.H
	router hashname.H
}

func (i *identifier) Hashname() hashname.H {
	return i.hn
}

func (i *identifier) String() string {
	return fmt.Sprint("{Peer: %s via=%s}", i.hn, i.router)
}

func (i *identifier) Identify(e *e3x.Endpoint) (*e3x.Identity, error) {
	var (
		mod    = FromEndpoint(e).(*module)
		router *e3x.Exchange
		target *e3x.Exchange
		err    error
	)

	router, err = e.Dial(e3x.Connected(i.router))
	if err != nil {
		return nil, err
	}

	target, err = mod.introduceVia(router, i.hn)
	if err != nil {
		return nil, err
	}

	return target.RemoteIdentity(), nil
}

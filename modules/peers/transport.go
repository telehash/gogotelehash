package peers

import (
	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = (*transportConfig)(nil)
)

type transportConfig struct {
	conf transports.Config
	mod  *module
}

func (t *transportConfig) Open() (transports.Transport, error) {
	sub, err := t.conf.Open()
	if err != nil {
		return nil, err
	}

	return &transport{sub, t.mod}, nil
}

type transport struct {
	t   transports.Transport
	mod *module
}

func (t *transport) LocalAddresses() []transports.Addr {
	return t.t.LocalAddresses()
}

func (t *transport) ReadMessage(p []byte) (n int, src transports.Addr, err error) {
	return t.t.ReadMessage(p)
}

func (t *transport) WriteMessage(p []byte, dst transports.Addr) error {
	a, ok := dst.(*addr)
	if a == nil || !ok {
		return t.t.WriteMessage(p, dst)
	}

	routerIdent, err := t.mod.e.Identify(e3x.HashnameIdentifier(a.router))
	if err != nil {
		return err
	}

	routerExch, err := t.mod.e.Dial(routerIdent)
	if err != nil {
		return err
	}

	// handshake
	if len(p) > 2 && p[0] == 0 && p[1] == 1 {
		return t.mod.peerVia(routerExch, a.target, p)
	}

	// channel packet
	routerPath := routerExch.ActivePath()
	if routerPath != nil {
		return t.t.WriteMessage(p, routerPath)
	}

	return nil // drop
}

func (t *transport) Close() error {
	return t.t.Close()
}

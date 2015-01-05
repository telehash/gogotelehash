package peers

import (
	"net"

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
	transports.Transport
	mod *module
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	if paddr, ok := addr.(*peerAddr); ok {
		routerEx := t.mod.e.GetExchange(paddr.router)
		if routerEx == nil {
			return nil, e3x.UnreachableEndpointError(paddr.router)
		}

		panic("must return actual peer connection")
	}

	return t.Transport.Dial(addr)
}

func (t *transport) ReadMessage(p []byte) (n int, src net.Addr, err error) {
	return t.t.ReadMessage(p)
}

func (t *transport) WriteMessage(p []byte, dst net.Addr) error {
	a, ok := dst.(*peerAddr)
	if a == nil || !ok {
		return t.t.WriteMessage(p, dst)
	}

	routerExch := t.mod.e.GetExchange(a.router)
	if routerExch == nil {
		return e3x.UnreachableEndpointError(a.router)
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

package bridge

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ net.Addr = (*peerAddr)(nil)
)

func init() {
	transports.RegisterAddr(&peerAddr{})

	transports.RegisterResolver("peer", func(addr string) (net.Addr, error) {
		hn := hashname.H(addr)
		if !hn.Valid() {
			return nil, transports.ErrInvalidAddr
		}
		return &peerAddr{hn}, nil
	})
}

type peerAddr struct {
	router hashname.H
}

func (a *peerAddr) Dial(e *e3x.Endpoint, x *e3x.Exchange) (net.Conn, error) {
	mod, _ := FromEndpoint(e).(*module)
	if mod == nil {
		return nil, net.UnknownNetworkError("unable to bridge")
	}

	router := e.GetExchange(a.router)
	if router == nil {
		return nil, net.UnknownNetworkError("unable to bridge")
	}

	conn := newConnection(x.RemoteHashname(), a, router, func() {
		mod.unregisterConnection(router, x.LocalToken())
	})

	mod.registerConnection(router, x.LocalToken(), conn)

	return conn, nil
}

func (*peerAddr) Network() string {
	return "peer"
}

func (a *peerAddr) String() string {
	return fmt.Sprintf("Peer{via: %q}", string(a.router[:8]))
}

func (a *peerAddr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		Hn   string `json:"hn"`
	}{
		Type: a.Network(),
		Hn:   string(a.router),
	}
	return json.Marshal(&desc)
}

func (a *peerAddr) UnmarshalJSON(p []byte) error {
	var desc struct {
		Type string `json:"type"`
		Hn   string `json:"hn"`
	}
	err := json.Unmarshal(p, &desc)
	if err != nil {
		return err
	}
	a.router = hashname.H(desc.Hn)
	return nil
}

func (a *peerAddr) Equal(x net.Addr) bool {
	b := x.(*peerAddr)

	if a.router != b.router {
		return false
	}

	return true
}

package peers

import (
	"encoding/json"
	"net"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ net.Addr = (*peerAddr)(nil)
)

func init() {
	transports.RegisterAddr(&peerAddr{})
}

type peerAddr struct {
	router hashname.H
}

func (*peerAddr) Network() string {
	return "peer"
}

func (a *peerAddr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
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

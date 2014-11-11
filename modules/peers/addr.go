package peers

import (
	"encoding/json"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ transports.Addr = (*addr)(nil)
)

type addr struct {
	target hashname.H
	router hashname.H
}

func (*addr) Network() string {
	return "peer"
}

func (a *addr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (a *addr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		Hn   string `json:"hn"`
	}{
		Type: a.Network(),
		Hn:   string(a.router),
	}
	return json.Marshal(&desc)
}

func (a *addr) Equal(x transports.Addr) bool {
	b := x.(*addr)

	if a.router != b.router {
		return false
	}

	return true
}

func (a *addr) Associate(hn hashname.H) transports.Addr {
	b := new(addr)
	*b = *a
	b.target = hn
	return b
}

func (a *addr) Hashname() hashname.H {
	return a.target
}

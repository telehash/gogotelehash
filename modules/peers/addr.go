package peers

import (
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ transports.Addr = (*addr)(nil)
)

type addr struct {
	router hashname.H
}

func (*addr) Network() string {
	return "peer"
}

func (*addr) String() string {
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
		Type: a.net,
		Hn:   string(a.router),
	}
	return json.Marshal(&desc)
}

func (a *addr) Equal(x Addr) bool {
	b := x.(*addr)

	if a.router != b.router {
		return false
	}

	return true
}

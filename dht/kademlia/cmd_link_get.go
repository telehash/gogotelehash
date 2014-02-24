package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type cmd_link_get struct {
	hashname telehash.Hashname
	link     *link_t
}

func (cmd *cmd_link_get) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	link, found := dht.links[cmd.hashname]
	if found {
		cmd.link = link
	}

	return nil
}

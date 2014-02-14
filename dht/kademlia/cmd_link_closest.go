package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type cmd_link_closest struct {
	target telehash.Hashname
	num    int
	links  []*link_t
}

func (cmd *cmd_link_closest) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	cmd.links = dht.table.find_closest(cmd.target, cmd.num)
	return nil
}

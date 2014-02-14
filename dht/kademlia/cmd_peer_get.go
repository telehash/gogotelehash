package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type cmd_peer_get struct {
	hashname telehash.Hashname
	peer     *telehash.Peer
}

func (cmd *cmd_peer_get) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	link, found := dht.links[cmd.hashname]
	if found {
		cmd.peer = link.peer
	}

	return nil
}

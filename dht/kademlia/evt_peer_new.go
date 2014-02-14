package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type evt_peer_new struct {
	peer *telehash.Peer
}

func (evt *evt_peer_new) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	panic("open link")
	return nil
}

package dht

import (
	"github.com/telehash/gogotelehash"
)

type DHT interface {
	telehash.Component

	// find a peer with the exact hashname
	Seek(hashname telehash.Hashname) (*telehash.Peer, error)

	// find the n closest peers
	SeekClosest(hashname telehash.Hashname, n int) ([]*telehash.Peer, error)

	// Get a peer without touching the network
	GetPeer(hashname telehash.Hashname) *telehash.Peer
}

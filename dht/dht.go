package dht

import (
	"crypto/rsa"
	"errors"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
)

var (
	ErrPeerNotFound = errors.New("dht: peer not found")
)

// DHTs must als implement telehash.Component
type DHT interface {
	// seed the dht
	Seed(net string, addr net.Addr, key *rsa.PublicKey) (telehash.Hashname, error)

	// find a peer with the exact hashname
	Seek(hashname telehash.Hashname) (*telehash.Peer, error)

	// find the n closest peers
	SeekMany(hashname telehash.Hashname, n int) ([]*telehash.Peer, error)
}

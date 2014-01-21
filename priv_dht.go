package telehash

import (
	"crypto/rsa"
	"github.com/telehash/gogotelehash/net"
)

// Copied from './dht/dht.go'
// So do not modify this without also modifying the real interface!!
type privDHT interface {
	Component
	Seed(net string, addr net.Addr, key *rsa.PublicKey) (Hashname, error)
	Seek(hashname Hashname) (*Peer, error)
	SeekMany(hashname Hashname, n int) ([]*Peer, error)
	GetPeer(hashname Hashname) *Peer
}

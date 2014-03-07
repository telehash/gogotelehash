package telehash

// Copied from './dht/dht.go'
// So do not modify this without also modifying the real interface!!
type privDHT interface {
	Component
	Seek(hashname Hashname) (*Peer, error)
	SeekClosest(hashname Hashname, n int) ([]*Peer, error)
	GetPeer(hashname Hashname) *Peer
}

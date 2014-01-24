package kademlia

import (
	"crypto/rsa"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
)

type DHT struct {
	sw    *telehash.Switch
	table peer_table
}

func (d *DHT) Start(sw *telehash.Switch) error {
	d.sw = sw
	d.table.Init(sw.LocalHashname())
	telehash.InternalMux(sw).HandleFunc("seek", d.serve_seek)
	return nil
}

func (d *DHT) Stop() error {
	return nil
}

func (d *DHT) GetPeer(hashname telehash.Hashname) *telehash.Peer {
	return d.table.get_peer(hashname)
}

func (d *DHT) Seed(net string, addr net.Addr, key *rsa.PublicKey) (telehash.Hashname, error) {

}

func (d *DHT) Seek(hashname telehash.Hashname) (*telehash.Peer, error) {
	peers, err := d.SeekMany(hashname, 5)
	if err != nil {
		return nil, err
	}

	if len(peers) == 0 {
		return nil, telehash.ErrPeerNotFound
	}

	peer := peers[0]
	if peer.Hashname() != hashname {
		return nil, telehash.ErrPeerNotFound
	}

	return peer, nil
}

func (d *DHT) SeekMany(hashname telehash.Hashname, n int) ([]*telehash.Peer, error) {

}

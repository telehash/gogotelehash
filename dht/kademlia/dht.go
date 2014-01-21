package kademlia

import (
	"crypto/rsa"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
	"time"
)

type DHT struct {
	sw    *telehash.Switch
	table peer_table
}

func (d *DHT) Start(sw *telehash.Switch) error {
	d.sw = sw
	d.table.Init(sw.LocalHashname())
	return nil
}

func (d *DHT) Stop() error {
	return nil
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

func (d *DHT) cmd_seek(hashname telehash.Hashname, via *telehash.Peer) []*telehash.Peer {
	type hdr_t struct {
		Seek string   `json:"seek,omitempty"`
		See  []string `json:"see,omitempty"`
	}

	options := telehash.ChannelOptions{
		Type:         "seek",
		Reliablility: telehash.UnreliableChannel,
	}

	header := hdr_t{
		Seek: hashname.String(),
	}

	channel, err := via.Open(options)
	if err != nil {
		// log error?
		return nil
	}

	defer channel.Close()

	channel.SetReceiveDeadline(time.Now().Add(10 * time.Second))

	_, err = channel.SendPacket(&header, nil)
	if err != nil {
		// log error?
		return nil
	}

	_, err = channel.ReceivePacket(&header, nil)
	if err != nil {
		// log error?
		return nil
	}

	// parse see header
	// fill buckets if necessary
}

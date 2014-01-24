package kademlia

import (
	"github.com/telehash/gogotelehash"
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

func (d *DHT) Seed(id *telehash.Identity) {

}

func (d *DHT) Seek(target telehash.Hashname) (*telehash.Peer, error) {
	// try local first
	peers := d.table.find_closest_peers(target, 5)
	for _, peer := range peers {
		if peer.Hashname() == target {
			return peer, nil
		}
	}

	var (
		in      = make(chan *telehash.Peer, len(peers))
		out     = make(chan *telehash.Peer)
		skip    = map[telehash.Hashname]bool{}
		pending int
	)

	defer close(in)
	defer close(out)

	// start some workers
	for i := 0; i < 5; i++ {
		go d.do_seek(target, in, out)
	}

	// enqueue with closest known peers
	for _, peer := range peers {
		skip[peer.Hashname()] = true
		pending++
		in <- peer
	}

	// handle results
	for peer := range out {
		// detect seek exhaustion
		if peer == nil {
			pending--
			if pending == 0 {
				break
			}
		}

		via := peer.Hashname()
		if via == target {
			return peer, nil // found peer
		} else if !skip[via] {
			// try to continue seeking
			skip[via] = true
			pending++
			in <- peer
		}
	}

	return nil, telehash.ErrPeerNotFound
}

func (d *DHT) SeekClosest(target telehash.Hashname, n int) ([]*telehash.Peer, error) {
	if n < 1 {
		return nil, nil
	}

	// get n closest known peers
	peers := d.table.find_closest_peers(target, n)

	var (
		in         = make(chan *telehash.Peer, len(peers))
		out        = make(chan *telehash.Peer)
		skip       = map[telehash.Hashname]bool{}
		candidates []*telehash.Peer
		pending    int
	)

	defer close(in)
	defer close(out)

	// start some workers
	for i := 0; i < 5; i++ {
		go d.do_seek(target, in, out)
	}

	// enqueue with closest known peers
	for _, peer := range peers {
		skip[peer.Hashname()] = true
		pending++
		in <- peer
	}

	// handle results
	for peer := range out {
		// detect seek exhaustion
		if peer == nil {
			pending--
			if pending == 0 {
				break
			}
		}

		candidates = append(candidates, peer)

		via := peer.Hashname()
		if !skip[via] {
			// try to continue seeking
			skip[via] = true
			pending++
			in <- peer
		}
	}

	kad_sort_peers(target, candidates)

	if len(candidates) > n {
		candidates = candidates[:n]
	}

	return candidates, nil
}

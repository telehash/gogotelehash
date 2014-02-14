package kademlia

import (
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/runloop"
)

type DHT struct {
	DisableSeed bool
	Seeds       []*telehash.Identity
	sw          *telehash.Switch
	table       seek_table
	links       map[telehash.Hashname]*link_t
	running     bool
	runloop     runloop.RunLoop
}

func (d *DHT) Start(sw *telehash.Switch) error {
	d.runloop.State = d
	d.sw = sw
	d.links = make(map[telehash.Hashname]*link_t)
	d.table.Init(sw.LocalHashname())
	telehash.InternalMux(sw).HandleFunc("seek", d.serve_seek)
	telehash.InternalMux(sw).HandleFunc("link", d.serve_link)

	d.runloop.Run()

	panic("open links")
	// for _, seed := range d.Seeds {
	//   peer := seed.ToPeer(sw)
	//   if peer != nil {
	//     d.table.add_peer(peer)
	//   }
	// }

	return nil
}

func (d *DHT) Stop() error {
	d.runloop.Cast(&cmd_shutdown{})
	return nil
}

func (d *DHT) GetPeer(hashname telehash.Hashname) *telehash.Peer {
	cmd := cmd_peer_get{hashname, nil}
	d.runloop.Call(&cmd)
	return cmd.peer
}

func (d *DHT) closest_links(target telehash.Hashname, num int) []*link_t {
	cmd := cmd_link_closest{target, num, nil}
	d.runloop.Call(&cmd)
	return cmd.links
}

func (d *DHT) OnNewPeer(peer *telehash.Peer) {
	d.runloop.Cast(&evt_peer_new{peer})
}

func (d *DHT) Seek(target telehash.Hashname) (*telehash.Peer, error) {
	// try local first
	links := d.closest_links(target, 5)
	for _, link := range links {
		peer := link.peer
		if peer.Hashname() == target {
			telehash.Log.Errorf("seek: peer=%s", peer)
			return peer, nil
		}
	}

	var (
		in      = make(chan *telehash.Peer, len(links))
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

	// enqueue with closest known links
	for _, link := range links {
		skip[link.peer.Hashname()] = true
		pending++
		in <- link.peer
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
			telehash.Log.Errorf("seek: peer=%s", peer)
			return peer, nil // found peer
		} else if !skip[via] {
			// try to continue seeking
			skip[via] = true
			pending++
			in <- peer
		}
	}

	telehash.Log.Errorf("seek: peer=(nil)")
	return nil, telehash.ErrPeerNotFound
}

func (d *DHT) SeekClosest(target telehash.Hashname, n int) ([]*telehash.Peer, error) {
	if n < 1 {
		return nil, nil
	}

	// get n closest known peers
	links := d.closest_links(target, n)

	var (
		in         = make(chan *telehash.Peer, len(links))
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

	// enqueue with closest known links
	for _, link := range links {
		skip[link.peer.Hashname()] = true
		pending++
		in <- link.peer
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

package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
	"time"
)

type peer_controller struct {
	sw             *Switch
	local_hashname Hashname
	buckets        [][]*peer_t
	mtx            sync.RWMutex
	log            log.Logger
}

func peer_controller_open(sw *Switch) (*peer_controller, error) {
	hashname, err := HashnameFromPublicKey(&sw.key.PublicKey)
	if err != nil {
		return nil, err
	}

	c := &peer_controller{
		sw:             sw,
		local_hashname: hashname,
		buckets:        make([][]*peer_t, 32*8),
		log:            sw.log.Sub(log_level_for("PEERS", log.DEFAULT), "peers"),
	}

	sw.mux.handle_func("seek", c.serve_seek)
	sw.mux.handle_func("peer", c.serve_peer)
	sw.mux.handle_func("connect", c.serve_connect)

	return c, nil
}

func (c *peer_controller) get_local_hashname() Hashname {
	return c.local_hashname
}

func (c *peer_controller) add_peer(addr addr_t) (peer *peer_t, discovered bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	peer = c._get_peer(addr.hashname)

	if peer == nil {
		// make new peer
		peer = make_peer(c.sw, addr.hashname)
		peer.addr = addr

		bucket := kad_bucket_for(c.get_local_hashname(), addr.hashname)

		// add the peer
		l := c.buckets[bucket]
		l = append(l, peer)
		c.buckets[bucket] = l

		discovered = true
	}

	if discovered {
		c.log.Noticef("discovered: %s", peer)
	}

	peer.addr.update(addr)

	return peer, discovered
}

func (c *peer_controller) remove_peer(peer *peer_t) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	var (
		bucket_idx = kad_bucket_for(c.get_local_hashname(), peer.addr.hashname)
		bucket     = c.buckets[bucket_idx]
		idx        = -1
	)

	for i, p := range bucket {
		if p == peer {
			idx = i
			break
		}
	}

	if idx == -1 {
		return
	}

	if len(bucket)-1 > idx {
		copy(bucket[idx:], bucket[idx+1:])
	}
	bucket = bucket[:len(bucket)-1]

	c.buckets[bucket_idx] = bucket
}

func (c *peer_controller) get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(c.get_local_hashname(), hashname)

	if bucket_index < 0 {
		return nil
	}

	c.mtx.RLock()
	bucket := c.buckets[bucket_index]
	c.mtx.RUnlock()

	for _, peer := range bucket {
		if peer.addr.hashname == hashname {
			return peer
		}
	}

	return nil
}

func (c *peer_controller) _get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(c.get_local_hashname(), hashname)

	if bucket_index < 0 {
		return nil
	}

	bucket := c.buckets[bucket_index]

	for _, peer := range bucket {
		if peer.addr.hashname == hashname {
			return peer
		}
	}

	return nil
}

func (c *peer_controller) find_closest_peers(t Hashname, n int) []*peer_t {
	bucket_index := kad_bucket_for(c.get_local_hashname(), t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		peers = make([]*peer_t, 0, 10)
	)

	for len(peers) < n {
		if 0 <= bucket_index+delta && bucket_index+delta < 32*8 {
			c.mtx.RLock()
			bucket := c.buckets[bucket_index+delta]
			c.mtx.RUnlock()
			peers = append(peers, bucket...)
		}

		if delta <= 0 {
			delta = -delta + 1
		} else {
			delta = -delta
		}

		if delta >= 32*8 {
			break
		}
	}

	kad_sort_peers(t, peers)

	if len(peers) > n {
		peers = peers[:n]
	}

	return peers
}

func (c *peer_controller) tick(now time.Time) {
	var (
		peers = make([]*peer_t, 0, 500)
	)

	c.mtx.RLock()
	for _, b := range c.buckets {
		peers = append(peers, b...)
	}
	c.mtx.RUnlock()

	for _, peer := range peers {
		peer.tick(now)
	}
}

func (c *peer_controller) rcv_pkt(outer_pkt *pkt_t) error {
	switch outer_pkt.hdr.Type {

	case "open":
		return c._rcv_open_pkt(outer_pkt)

	default:
		// c.log.Debugf("rcv pkt err=%s pkt=%#v", errInvalidPkt, outer_pkt)
		return errInvalidPkt

	}
}

func (c *peer_controller) _rcv_open_pkt(opkt *pkt_t) error {
	pub_line_half, err := decompose_open_pkt(c.sw.key, opkt)
	if err != nil {
		return err
	}

	peer := c.get_peer(pub_line_half.hashname)
	if peer == nil {
		addr := addr_t{hashname: pub_line_half.hashname, pubkey: pub_line_half.rsa_pubkey}
		addr.update(opkt.addr)
		peer, _ = c.add_peer(addr)
	}

	peer.line.RcvOpen(pub_line_half)

	return nil
}

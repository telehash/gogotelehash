package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type peer_table struct {
	local_hashname telehash.Hashname
	num_peers      uint32
	buckets        [][]*telehash.Peer
}

func (c *peer_table) Init(local_hashname telehash.Hashname) {
	c.local_hashname = local_hashname
	c.buckets = make([][]*telehash.Peer, 32*8)
}

func (c *peer_table) add_peer(sw *Switch, hashname telehash.Hashname) (peer *telehash.Peer, discovered bool) {
	peer = c.get_peer(hashname)

	if peer == nil {
		c.num_peers++

		// make new peer
		peer = make_peer(sw, hashname)

		// determine bucket for HN
		bucket := kad_bucket_for(c.local_hashname, peer.Hashname())

		// add the peer
		l := c.buckets[bucket]
		l = append(l, peer)
		c.buckets[bucket] = l

		discovered = true
	}

	return peer, discovered
}

func (c *peer_table) remove_peer(peer *telehash.Peer) {
	var (
		bucket_idx = kad_bucket_for(c.local_hashname, peer.Hashname())
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
	c.num_peers--
}

func (c *peer_table) get_peer(hashname telehash.Hashname) *telehash.Peer {
	bucket_index := kad_bucket_for(c.local_hashname, hashname)

	if bucket_index < 0 {
		return nil
	}

	bucket := c.buckets[bucket_index]

	for _, peer := range bucket {
		if peer.Hashname() == hashname {
			return peer
		}
	}

	return nil
}

func (c *peer_table) find_closest_peers(t telehash.Hashname, n int) []*telehash.Peer {
	bucket_index := kad_bucket_for(c.local_hashname, t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		peers = make([]*Peer, 0, 10)
	)

	for len(peers) < n {
		if 0 <= bucket_index+delta && bucket_index+delta < 32*8 {
			bucket := c.buckets[bucket_index+delta]
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

package telehash

type peer_table struct {
	local_hashname Hashname
	num_peers      uint32
	buckets        [][]*peer_t
}

func (c *peer_table) Init(local_hashname Hashname) {
	c.local_hashname = local_hashname
	c.buckets = make([][]*peer_t, 32*8)
}

func (c *peer_table) add_peer(addr addr_t) (peer *peer_t, discovered bool) {
	peer = c.get_peer(addr.hashname)

	if peer == nil {
		c.num_peers++

		// make new peer
		peer = make_peer(addr.hashname)
		peer.addr = addr

		bucket := kad_bucket_for(c.local_hashname, addr.hashname)

		// add the peer
		l := c.buckets[bucket]
		l = append(l, peer)
		c.buckets[bucket] = l

		discovered = true
	}

	peer.addr.update(addr)

	return peer, discovered
}

func (c *peer_table) remove_peer(peer *peer_t) {
	var (
		bucket_idx = kad_bucket_for(c.local_hashname, peer.addr.hashname)
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

func (c *peer_table) get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(c.local_hashname, hashname)

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

func (c *peer_table) find_closest_peers(t Hashname, n int) []*peer_t {
	bucket_index := kad_bucket_for(c.local_hashname, t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		peers = make([]*peer_t, 0, 10)
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

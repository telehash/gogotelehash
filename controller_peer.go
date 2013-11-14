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

	h := &peer_controller{
		sw:             sw,
		local_hashname: hashname,
		buckets:        make([][]*peer_t, 32*8),
		log:            sw.log.Sub(log.NOTICE, "peers"),
	}

	sw.mux.handle_func("seek", h.serve_seek)
	sw.mux.handle_func("peer", h.serve_peer)
	sw.mux.handle_func("connect", h.serve_connect)

	return h, nil
}

func (h *peer_controller) get_local_hashname() Hashname {
	return h.local_hashname
}

func (h *peer_controller) add_peer(addr addr_t) (peer *peer_t, discovered bool) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	peer = h._get_peer(addr.hashname)

	if peer == nil {
		// make new peer
		peer = make_peer(h.sw, addr.hashname)
		peer.addr = addr

		bucket := kad_bucket_for(h.get_local_hashname(), addr.hashname)

		// add the peer
		l := h.buckets[bucket]
		l = append(l, peer)
		h.buckets[bucket] = l

		discovered = true
	}

	peer.addr.update(addr)

	return peer, discovered
}

func (h *peer_controller) get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(h.get_local_hashname(), hashname)

	if bucket_index < 0 {
		return nil
	}

	h.mtx.RLock()
	bucket := h.buckets[bucket_index]
	h.mtx.RUnlock()

	for _, peer := range bucket {
		if peer.addr.hashname == hashname {
			return peer
		}
	}

	return nil
}

func (h *peer_controller) _get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(h.get_local_hashname(), hashname)

	if bucket_index < 0 {
		return nil
	}

	bucket := h.buckets[bucket_index]

	for _, peer := range bucket {
		if peer.addr.hashname == hashname {
			return peer
		}
	}

	return nil
}

func (h *peer_controller) find_closest_peers(t Hashname, n int) []*peer_t {
	bucket_index := kad_bucket_for(h.get_local_hashname(), t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		peers = make([]*peer_t, 0, 10)
	)

	for len(peers) < n {
		if 0 <= bucket_index+delta && bucket_index+delta < 32*8 {
			h.mtx.RLock()
			bucket := h.buckets[bucket_index+delta]
			h.mtx.RUnlock()
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

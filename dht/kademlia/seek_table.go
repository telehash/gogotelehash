package kademlia

import (
	"github.com/telehash/gogotelehash"
)

type seek_table struct {
	local_hashname telehash.Hashname
	num_links      uint32
	buckets        [][]*link_t
}

func (c *seek_table) Init(local_hashname telehash.Hashname) {
	c.local_hashname = local_hashname
	c.buckets = make([][]*link_t, 32*8)
}

func (c *seek_table) add(link *link_t) bool {
	if link == nil {
		return false
	}

	if c.get(link.peer.Hashname()) == nil {
		c.num_links++

		// determine bucket for HN
		bucket := link.log_distance

		// add the peer
		l := c.buckets[bucket]
		l = append(l, link)
		c.buckets[bucket] = l

		return true
	}

	return false
}

func (c *seek_table) remove(link *link_t) {
	var (
		bucket_idx = link.log_distance
		bucket     = c.buckets[bucket_idx]
		idx        = -1
	)

	for i, l := range bucket {
		if l == link {
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
	c.num_links--
}

func (c *seek_table) get(hashname telehash.Hashname) *link_t {
	bucket_index := kad_bucket_for(c.local_hashname, hashname)

	if bucket_index < 0 {
		return nil
	}

	bucket := c.buckets[bucket_index]

	for _, link := range bucket {
		if link.peer.Hashname() == hashname {
			return link
		}
	}

	return nil
}

func (c *seek_table) find_closest(t telehash.Hashname, n int) []*link_t {
	bucket_index := kad_bucket_for(c.local_hashname, t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		links = make([]*link_t, 0, 10)
	)

	for len(links) < n {
		if 0 <= bucket_index+delta && bucket_index+delta < 32*8 {
			bucket := c.buckets[bucket_index+delta]
			links = append(links, bucket...)
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

	kad_sort_links(t, links)

	if len(links) > n {
		links = links[:n]
	}

	return links
}

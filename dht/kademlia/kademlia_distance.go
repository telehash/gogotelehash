package kademlia

import (
	"bytes"
	"github.com/telehash/gogotelehash"
	"sort"
)

type kad_distance [32]byte

func kad_sort_by_distance(target telehash.Hashname, list []telehash.Hashname) {
	s := hashname_sorter{
		target: target,
		list:   list,
		dist:   make([]kad_distance, len(list)),
	}

	for i, hashname := range list {
		s.dist[i] = kad_distance_between(target, hashname)
	}

	sort.Sort(&s)
}

type hashname_sorter struct {
	target telehash.Hashname
	list   []telehash.Hashname
	dist   []kad_distance
}

func (l *hashname_sorter) Len() int {
	return len(l.list)
}

func (l *hashname_sorter) Less(i, j int) bool {
	return kad_compare(l.dist[i], l.dist[j]) < 0
}

func (l *hashname_sorter) Swap(i, j int) {
	l.list[i], l.list[j] = l.list[j], l.list[i]
	l.dist[i], l.dist[j] = l.dist[j], l.dist[i]
}

func kad_sort_peers(target telehash.Hashname, list []*telehash.Peer) {
	s := peer_sorter{
		target: target,
		list:   list,
		dist:   make([]kad_distance, len(list)),
	}

	for i, peer := range list {
		s.dist[i] = kad_distance_between(target, peer.Hashname())
	}

	sort.Sort(&s)
}

type peer_sorter struct {
	target telehash.Hashname
	list   []*telehash.Peer
	dist   []kad_distance
}

func (l *peer_sorter) Len() int {
	return len(l.list)
}

func (l *peer_sorter) Less(i, j int) bool {
	return kad_compare(l.dist[i], l.dist[j]) < 0
}

func (l *peer_sorter) Swap(i, j int) {
	l.list[i], l.list[j] = l.list[j], l.list[i]
	l.dist[i], l.dist[j] = l.dist[j], l.dist[i]
}

func kad_sort_links(target telehash.Hashname, list []*link_t) {
	s := link_sorter{
		target: target,
		list:   list,
		dist:   make([]kad_distance, len(list)),
	}

	for i, link := range list {
		s.dist[i] = kad_distance_between(target, link.peer.Hashname())
	}

	sort.Sort(&s)
}

type link_sorter struct {
	target telehash.Hashname
	list   []*link_t
	dist   []kad_distance
}

func (l *link_sorter) Len() int {
	return len(l.list)
}

func (l *link_sorter) Less(i, j int) bool {
	return kad_compare(l.dist[i], l.dist[j]) < 0
}

func (l *link_sorter) Swap(i, j int) {
	l.list[i], l.list[j] = l.list[j], l.list[i]
	l.dist[i], l.dist[j] = l.dist[j], l.dist[i]
}

func kad_distance_between(a, b telehash.Hashname) kad_distance {
	var (
		d kad_distance
	)

	for i := 0; i < 32; i++ {
		d[i] = a[i] ^ b[i]
	}

	return d
}

func kad_compare(a, b kad_distance) int {
	return bytes.Compare(a[:], b[:])
}

func (k kad_distance) bucket_index() int {
	b := 32 * 8

	for i := 0; i < 32; i++ {
		c := k[i]

		if c == 0 {
			b -= 8
			continue
		}

		switch {
		case c >= 0x40:
			return b - 1

		case c >= 0x20:
			return b - 2

		case c >= 0x10:
			return b - 3

		case c >= 0x08:
			return b - 4

		case c >= 0x04:
			return b - 5

		case c >= 0x02:
			return b - 6

		case c >= 0x01:
			return b - 7

		}
	}

	return -1
}

func kad_bucket_for(a, b telehash.Hashname) int {
	bucket := 32 * 8

	for i := 0; i < 32; i++ {
		c := a[i] ^ b[i]

		if c == 0 {
			bucket -= 8
			continue
		}

		switch {
		case c >= 0x40:
			return bucket - 1

		case c >= 0x20:
			return bucket - 2

		case c >= 0x10:
			return bucket - 3

		case c >= 0x08:
			return bucket - 4

		case c >= 0x04:
			return bucket - 5

		case c >= 0x02:
			return bucket - 6

		case c >= 0x01:
			return bucket - 7

		}
	}

	return -1
}

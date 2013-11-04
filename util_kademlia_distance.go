package telehash

import (
	"bytes"
	"sort"
)

func (h *peer_handler) find_closest_hashnames(t string, n int) []string {
	hashnames := make([]string, 0, len(h.peers))

	for hn, peer := range h.peers {
		if peer.pubkey == nil {
			continue
		}

		hashnames = append(hashnames, hn)
	}

	SortByDistance(h.get_local_hashname(), hashnames)

	if len(hashnames) > n {
		hashnames = hashnames[:n]
	}

	return hashnames
}

type hashname_sorter struct {
	target string
	list   []string
	dist   [][]byte
}

func SortByDistance(target string, list []string) {
	s := hashname_sorter{
		target: target,
		list:   list,
		dist:   make([][]byte, len(list)),
	}

	t := []byte(target)

	for i, hashname := range list {
		b := []byte(hashname)
		d := make([]byte, len(b))
		for i, a := range b {
			d[i] = t[i] ^ a
		}
		s.dist[i] = d
	}

	sort.Sort(&s)
}

func (l *hashname_sorter) Len() int {
	return len(l.list)
}

func (l *hashname_sorter) Less(i, j int) bool {
	return bytes.Compare(l.dist[i], l.dist[j]) < 0
}

func (l *hashname_sorter) Swap(i, j int) {
	l.list[i], l.list[j] = l.list[j], l.list[i]
	l.dist[i], l.dist[j] = l.dist[j], l.dist[i]
}

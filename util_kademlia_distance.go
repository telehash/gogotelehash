package telehash

import (
	"bytes"
	"sort"
)

type kad_distance [32]byte

type hashname_sorter struct {
	target Hashname
	list   []Hashname
	dist   []kad_distance
}

func kad_sort_by_distance(target Hashname, list []Hashname) {
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

func kad_distance_between(a, b Hashname) kad_distance {
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

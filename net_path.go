package telehash

import (
	"sync/atomic"
)

type NetPath interface {
	Priority() int
	ResetPriority()
	SendOpen()
	Hash() uint32
	AddressForSeek() (ip string, port int, ok bool)
	AddressForPeer() (ip string, port int, ok bool)
	SendNatBreaker() bool
	Send(sw *Switch, pkt *pkt_t) error
}

func EqualNetPaths(a, b NetPath) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Hash() == b.Hash()
}

type net_path_priority int32

func (n *net_path_priority) Get() int {
	return int(atomic.LoadInt32((*int32)(n)))
}

func (n *net_path_priority) Add(i int) {
	atomic.AddInt32((*int32)(n), int32(i))
}

func (n *net_path_priority) Reset() {
	atomic.StoreInt32((*int32)(n), 0)
}

type net_path_sorter []NetPath

func (l net_path_sorter) Len() int           { return len(l) }
func (l net_path_sorter) Less(i, j int) bool { return l[i].Priority() > l[j].Priority() }
func (l net_path_sorter) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }

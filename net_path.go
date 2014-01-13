package telehash

import (
	"github.com/telehash/gogotelehash/net"
	"sync/atomic"
)

type net_path struct {
	Network  string
	Address  net.Addr
	priority int32
}

func equal_net_paths(a, b *net_path) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Network != b.Network {
		return false
	}
	return a.Address.EqualTo(b.Address)
}

type net_path_priority int32

func (n *net_path) Priority() int {
	return int(atomic.LoadInt32(&n.priority)) + n.Address.DefaultPriority()
}

func (n *net_path) Demote() {
	atomic.AddInt32(&n.priority, -1)
}

func (n *net_path) Break() {
	atomic.AddInt32(&n.priority, int32(-3-n.Address.DefaultPriority()))
}

func (n *net_path) ResetPriority() {
	atomic.StoreInt32(&n.priority, 0)
}

type net_path_sorter net_paths

func (l net_path_sorter) Len() int           { return len(l) }
func (l net_path_sorter) Less(i, j int) bool { return l[i].Priority() > l[j].Priority() }
func (l net_path_sorter) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }

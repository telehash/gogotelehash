package telehash

import (
	"crypto/rsa"
	"fmt"
	"github.com/telehash/gogotelehash/net"
	"sort"
	"sync"
)

type Peer struct {
	sw           *Switch
	hashname     Hashname
	paths        net_paths
	active_paths net_paths
	pubkey       *rsa.PublicKey
	via          map[Hashname]bool
	mtx          sync.RWMutex
}

func make_peer(sw *Switch, hashname Hashname) *Peer {
	peer := &Peer{
		sw:       sw,
		hashname: hashname,
		via:      make(map[Hashname]bool),
	}

	return peer
}

func (p *Peer) Open(options ChannelOptions) (*Channel, error) {
	if p == nil {
		return nil, ErrPeerNotFound
	}
	options.to = p.hashname
	return p.sw.open_channel(options)
}

func (p *Peer) String() string {
	return fmt.Sprintf("<peer:%s>", p.hashname.Short())
}

func (p *Peer) Hashname() Hashname {
	return p.hashname
}

func (p *Peer) IsConnected() bool {
	return p.sw.get_active_line(p.hashname) != nil
}

// Get the public key of the peer. Returns nil when the public key is unknown.
func (p *Peer) PublicKey() *rsa.PublicKey {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pubkey
}

// Set the public key for this peer. Does nothing when the public key is already set.
func (p *Peer) set_public_key(key *rsa.PublicKey) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.pubkey == nil {
		p.pubkey = key
	}
}

// add a peer known to be connected to this peer
func (p *Peer) AddVia(hashname Hashname) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.via[hashname] = true
}

// Get the table of known via peers
func (p *Peer) ViaTable() []Hashname {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	m := make([]Hashname, len(p.via))
	i := 0
	for h := range p.via {
		m[i] = h
		i++
	}

	return m
}

func (p *Peer) net_paths() net_paths {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	paths := make(net_paths, len(p.paths))
	copy(paths, p.paths)
	return paths
}

func (p *Peer) AddAddress(network string, address net.Addr) {
	p.add_net_path(&net_path{Network: network, Address: address})
}

func (p *Peer) add_net_path(netpath *net_path) *net_path {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	for _, np := range p.paths {
		if equal_net_paths(np, netpath) {
			return np
		}
	}

	p.paths = append(p.paths, netpath)
	return netpath
}

func (p *Peer) remove_net_path(netpath *net_path) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var (
		paths net_paths
	)

	for _, np := range p.paths {
		if !equal_net_paths(np, netpath) {
			paths = append(paths, np)
		}
	}

	p.paths = paths
}

func (p *Peer) update_paths() {
	sort.Sort(net_path_sorter(p.active_paths))

	for i, np := range p.active_paths {
		if np.Priority() < -3 {
			p.active_paths = p.active_paths[:i]
			break
		}
	}
}

func (p *Peer) active_path() *net_path {
	if p == nil {
		return nil
	}

	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if len(p.active_paths) == 0 {
		return nil
	}

	return p.active_paths[0]
}

func (p *Peer) set_active_paths(paths net_paths) {
	if p == nil {
		return
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.active_paths = paths
	p.update_paths()
}

func (p *Peer) can_open() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pubkey != nil && len(p.paths) > 0 || len(p.via) > 0
}

func (peer *Peer) FormatSeeAddress() []string {
	if peer == nil {
		return nil
	}

	for _, np := range peer.net_paths() {
		if np.Address.PublishWithSeek() {
			if fields, err := net.EncodeSee(np.Network, np.Address); err == nil && len(fields) > 0 {
				return fields
			}
		}
	}

	return nil
}

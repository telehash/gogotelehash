package telehash

import (
	"crypto/rsa"
	"fmt"
	"sort"
	"sync"
)

type Peer struct {
	sw           *Switch
	hashname     Hashname
	paths        NetPaths
	active_paths NetPaths
	pubkey       *rsa.PublicKey
	is_down      bool
	via          map[Hashname]bool
	mtx          sync.RWMutex
}

func make_peer(sw *Switch, hashname Hashname) *Peer {
	peer := &Peer{
		hashname: hashname,
		via:      make(map[Hashname]bool),
	}

	return peer
}

func (p *Peer) String() string {
	return fmt.Sprintf("<peer:%s>", p.hashname.Short())
}

func (p *Peer) Hashname() Hashname {
	return p.hashname
}

// Get the public key of the peer. Returns nil when the public key is unknown.
func (p *Peer) PublicKey() *rsa.PublicKey {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pubkey
}

// Set the public key for this peer. Does nothing when the public key is already set.
func (p *Peer) SetPublicKey(key *rsa.PublicKey) {
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

func (p *Peer) NetPaths() NetPaths {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	paths := make(NetPaths, len(p.paths))
	copy(paths, p.paths)
	return paths
}

func (p *Peer) AddNetPath(netpath NetPath) NetPath {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var (
		found = false
	)

	for _, np := range p.paths {
		if EqualNetPaths(np, netpath) {
			netpath = np
			found = true
			break
		}
	}

	if !found {
		p.paths = append(p.paths, netpath)
	}

	return netpath
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

func (p *Peer) ActivePath() NetPath {
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

func (p *Peer) set_active_paths(paths NetPaths) {
	if p == nil {
		return
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.active_paths = paths
	p.update_paths()
}

func (p *Peer) CanOpen() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pubkey != nil && len(p.paths) > 0 || len(p.via) > 0
}

func (p *Peer) MustSendPeer() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pubkey == nil && len(p.via) > 0
}

func (p *Peer) HasVia() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return len(p.via) > 0
}

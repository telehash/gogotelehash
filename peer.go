package telehash

import (
	"crypto/rsa"
	"fmt"
	"sync"
)

type Peer struct {
	sw         *Switch
	hashname   Hashname
	paths      []NetPath
	pubkey     *rsa.PublicKey
	is_down    bool
	via        map[Hashname]bool
	pkt_sender packet_sender
	mtx        sync.RWMutex
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

func (p *Peer) NetPaths() []NetPath {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	paths := make([]NetPath, len(p.paths))
	copy(paths, p.paths)
	return paths
}

func (p *Peer) AddNetPath(netpath NetPath) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var (
		found = false
		y     = 0
	)

	for i, np := range p.paths {
		if EqualNetPaths(np, netpath) {
			found = true
			y = i
			break
		}
	}

	if !found {
		y = len(p.paths)
		p.paths = append(p.paths, netpath)
		if y == 0 {
			p.pkt_sender = p.paths[0].packet_sender()
		}
	}

	if y != 0 {
		p.paths[0], p.paths[y] = p.paths[y], p.paths[0]
		p.pkt_sender = p.paths[0].packet_sender()
	}
}

func (p *Peer) packet_sender() packet_sender {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.pkt_sender
}

func (p *Peer) CanOpen() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return (p.pubkey != nil || len(p.via) > 0) && len(p.paths) > 0
}

func (p *Peer) HasVia() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return len(p.via) > 0
}

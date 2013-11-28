package telehash

import (
	"crypto/rsa"
	"net"
	"sync"
)

type Peer struct {
	hashname Hashname
	paths    []NetPath
	pubkey   *rsa.PublicKey
	is_down  bool
	via      map[Hashname]bool
	mtx      sync.RWMutex
}

func make_peer(hashname Hashname) *Peer {
	peer := &Peer{
		addr: addr_t{hashname: hashname},
		via:  make(map[Hashname]bool),
	}

	return peer
}

func (p *Peer) String() string {
	return p.addr.String()
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
func (p *Peer) AddVia(hashname Hashname, addr string) error {
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.via[Hashname] = udp
	return nil
}

// Get the table of known via peers
func (p *Peer) ViaTable() map[Hashname]*net.UDPAddr {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	m := make(map[Hashname]*net.UDPAddr, len(p.addr))
	for h, a := range p.via {
		m[h] = v
	}

	return m
}

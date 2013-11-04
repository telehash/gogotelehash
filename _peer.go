package telehash

import (
	"crypto/rsa"
	"net"
	"sync"
)

type peer_t struct {
	_switch  *Switch
	hashname string
	addr     *net.UDPAddr
	pubkey   *rsa.PublicKey
	line     *line_t
	line_cnd sync.Cond
	line_mtx sync.RWMutex
}

func make_peer(s *Switch, hashname string, addr *net.UDPAddr, pubkey *rsa.PublicKey) *peer_t {
	peer := &peer_t{_switch: s, hashname: hashname, addr: addr, pubkey: pubkey}
	peer.line_cnd.L = peer.line_mtx.RLocker()
	return peer
}

func (p *peer_t) set_line(l *line_t) {
	p.line_mtx.Lock()
	defer p.line_mtx.Unlock()

	p.line = l
	p.line_cnd.Broadcast()
}

func (p *peer_t) get_line() *line_t {
	locker := p.line_mtx.RLocker()
	locker.Lock()
	defer locker.Unlock()

	for p.line == nil {
		if p._switch.i_open[p.hashname] == nil &&
			p._switch.o_open[p.hashname] == nil {
			p._switch.open_line(p.hashname)
		}

		p.line_cnd.Wait()
	}

	return p.line
}

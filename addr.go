package telehash

import (
	"crypto/rsa"
	"fmt"
	"net"
)

type addr_t struct {
	hashname Hashname
	via      Hashname
	pubkey   *rsa.PublicKey
	addr     *net.UDPAddr
}

func make_addr(hashname, via Hashname, addr string, pubkey *rsa.PublicKey) (addr_t, error) {

	// resolve the address
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return addr_t{}, err
	}

	// determine the hashname
	if hashname.IsZero() {
		if pubkey == nil {
			return addr_t{}, fmt.Errorf("pubkey must not be nil")
		}

		hashname, err = HashnameFromPublicKey(pubkey)
		if err != nil {
			return addr_t{}, err
		}
	}

	return addr_t{hashname: hashname, via: via, addr: udp_addr, pubkey: pubkey}, nil
}

func (p addr_t) String() string {
	if p.via.IsZero() {
		return fmt.Sprintf("<peer:%s addr=%s>", p.hashname.Short(), p.addr)
	} else {
		return fmt.Sprintf("<peer:%s addr=%s via=%s>", p.hashname.Short(), p.addr, p.via.Short())
	}
}

func (a *addr_t) update(b addr_t) {
	if b.addr != nil {
		if a.addr == nil || !is_lan_ip(a.addr.IP) || is_lan_ip(b.addr.IP) {
			a.addr = b.addr
		}
	}

	if a.pubkey == nil && b.pubkey != nil {
		a.pubkey = b.pubkey
	}

	if !b.via.IsZero() {
		a.via = b.via
	}
}

package telehash

type peer_t struct {
	addr              addr_t
	line_open_retries int
}

func make_peer(hashname Hashname) *peer_t {
	peer := &peer_t{
		addr: addr_t{hashname: hashname},
	}

	return peer
}

func (p *peer_t) String() string {
	return p.addr.String()
}

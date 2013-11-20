package telehash

type peer_t struct {
	addr addr_t
}

func make_peer(hashname Hashname) *peer_t {
	peer := &peer_t{
		addr: addr_t{hashname: hashname},
	}

	return peer
}

// func (p *peer_t) IsGood() bool {
//   return p.line.State().test(line_opened, 0)
// }

func (p *peer_t) String() string {
	return p.addr.String()
}

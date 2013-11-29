package telehash

type NetPath interface {
	Priority() int
	Hash() uint32
	AddressForSeek() (ip string, port int, ok bool)
	AddressForPeer() (ip string, port int, ok bool)
	packet_sender() packet_sender
}

type packet_sender interface {
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

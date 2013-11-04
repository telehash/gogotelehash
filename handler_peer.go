package telehash

import (
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
)

type peer_t struct {
	hashname string
	pubkey   *rsa.PublicKey
	addr     *net.UDPAddr
}

type peer_handler struct {
	conn      *line_handler
	rcv       chan *pkt_t
	peers     map[string]*peer_t
	peers_mtx sync.RWMutex
}

func peer_handler_open(addr string, prvkey *rsa.PrivateKey) (*peer_handler, error) {
	conn, err := line_handler_open(addr, prvkey)
	if err != nil {
		return nil, err
	}

	h := &peer_handler{
		conn:  conn,
		rcv:   conn.rcv,
		peers: make(map[string]*peer_t),
	}

	conn.new_peer_handler = h.discover_new_peer

	return h, nil
}

func (h *peer_handler) get_local_hashname() string {
	return h.conn.get_local_hashname()
}

func (h *peer_handler) close() {
	h.conn.close()
}

func (h *peer_handler) discover_new_peer(hashname string, addr *net.UDPAddr, pubkey *rsa.PublicKey) {
	h.peers_mtx.Lock()
	defer h.peers_mtx.Unlock()

	h.peers[hashname] = &peer_t{
		hashname: hashname,
		pubkey:   pubkey,
		addr:     addr,
	}
}

func (h *peer_handler) add_peer(addr string, pubkey *rsa.PublicKey) (string, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}

	hashname, err := hashname_from_RSA(pubkey)
	if err != nil {
		return "", err
	}

	h.peers_mtx.Lock()
	defer h.peers_mtx.Unlock()

	h.peers[hashname] = &peer_t{
		hashname: hashname,
		pubkey:   pubkey,
		addr:     udp_addr,
	}

	return hashname, nil
}

func (h *peer_handler) remove_peer(hashname string) {
	h.peers_mtx.Lock()
	defer h.peers_mtx.Unlock()

	delete(h.peers, hashname)
}

func (h *peer_handler) send(hashname string, pkt *pkt_t) error {
	peer := h.get_peer(hashname)
	if peer == nil {
		return fmt.Errorf("unknown peer: %s", hashname)
	}

	err := h.conn.open_line(peer.addr, peer.pubkey)
	if err != nil {
		return err
	}

	return h.conn.send(hashname, pkt)
}

func (h *peer_handler) get_peer(hashname string) *peer_t {
	h.peers_mtx.RLock()
	defer h.peers_mtx.RUnlock()

	return h.peers[hashname]
}

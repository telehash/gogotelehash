package telehash

import (
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type peer_t struct {
	hashname string
	pubkey   *rsa.PublicKey
	addr     *net.UDPAddr
}

type peer_handler struct {
	conn           *channel_handler
	local_hashname string
	peers          map[string]*peer_t
	peers_mtx      sync.RWMutex
}

func peer_handler_open(prvkey *rsa.PrivateKey, mux *SwitchMux) (*peer_handler, error) {
	hashname, err := hashname_from_RSA(&prvkey.PublicKey)
	if err != nil {
		return nil, err
	}

	h := &peer_handler{
		local_hashname: hashname,
		peers:          make(map[string]*peer_t),
	}

	mux.handle_func("seek", h.serve_seek)
	mux.handle_func("peer", h.serve_peer)
	mux.handle_func("connect", h.serve_connect)

	return h, nil
}

func (h *peer_handler) get_local_hashname() string {
	return h.local_hashname
}

func (h *peer_handler) add_peer(hashname, addr string, pubkey *rsa.PublicKey) (string, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}

	if hashname == "" {
		hashname, err = hashname_from_RSA(pubkey)
		if err != nil {
			return "", err
		}
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

func (h *peer_handler) get_peer(hashname string) *peer_t {
	h.peers_mtx.RLock()
	defer h.peers_mtx.RUnlock()

	return h.peers[hashname]
}

func (h *peer_handler) find_closest_hashnames(t string, n int) []string {
	h.peers_mtx.RLock()
	defer h.peers_mtx.RUnlock()

	hashnames := make([]string, 0, len(h.peers))

	for hn := range h.peers {
		hashnames = append(hashnames, hn)
	}

	SortByDistance(h.local_hashname, hashnames)

	if len(hashnames) > n {
		hashnames = hashnames[:n]
	}

	return hashnames
}

func (h *peer_handler) seek(hashname string, n int) []string {
	var (
		wg   sync.WaitGroup
		last = h.find_closest_hashnames(hashname, n)
	)

RECURSOR:
	for {
		for _, to := range last {
			if to != h.get_local_hashname() {
				wg.Add(1)
				go h.send_seek_cmd(to, hashname, &wg)
			}
		}

		wg.Wait()

		curr := h.find_closest_hashnames(hashname, n)
		if len(curr) != len(last) {
			last = curr
			continue RECURSOR
		}

		for i, a := range last {
			if a != curr[i] {
				last = curr
				continue RECURSOR
			}
		}

		break
	}

	return last
}

func (h *peer_handler) send_seek_cmd(to, seek string, wg *sync.WaitGroup) {
	defer wg.Done()

	local_hashname := h.get_local_hashname()

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "seek",
			Seek: seek,
		},
	}

	channel, err := h.conn.open_channel(to, pkt)
	if err != nil {
		Log.Debugf("failed to seek %s (error: %s)", to, err)
		return
	}
	defer channel.close()

	channel.SetReceiveDeadline(time.Now().Add(15 * time.Second))

	reply, err := channel.receive()
	if err != nil {
		Log.Debugf("failed to seek %s (error: %s)", to, err)
		return
	}

	for _, rec := range reply.hdr.See {
		fields := strings.Split(rec, ",")

		if len(fields) != 3 {
			continue
		}

		var (
			hashname = fields[0]
			ip       = fields[1]
			port     = fields[2]
			addr     = net.JoinHostPort(ip, port)
		)

		if hashname == local_hashname {
			continue
		}

		_, err := h.add_peer(hashname, addr, nil)
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
		}
	}
}

func (h *peer_handler) serve_seek(channel *channel_t) {
	pkt, err := channel.receive()
	if err != nil {
		return // drop
	}

	closest := h.find_closest_hashnames(pkt.hdr.Seek, 25)
	see := make([]string, 0, len(closest))

	for _, hashname := range closest {
		peer := h.get_peer(hashname)
		if peer == nil {
			continue
		}
		if peer.pubkey == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		see = append(see, fmt.Sprintf("%s,%s,%d", hashname, peer.addr.IP, peer.addr.Port))
	}

	err = channel.send(&pkt_t{
		hdr: pkt_hdr_t{
			See: see,
			End: true,
		},
	})
	if err != nil {
		return
	}
}

func (h *peer_handler) serve_peer(channel *channel_t) {
}

func (h *peer_handler) serve_connect(channel *channel_t) {
}

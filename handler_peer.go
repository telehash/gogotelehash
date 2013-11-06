package telehash

import (
	"crypto/rsa"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type peer_t struct {
	hashname Hashname
	via      Hashname
	pubkey   *rsa.PublicKey
	addr     *net.UDPAddr
}

type peer_handler struct {
	conn           *channel_handler
	local_hashname Hashname
	peers          map[Hashname]*peer_t
	peers_mtx      sync.RWMutex
}

func peer_handler_open(prvkey *rsa.PrivateKey, mux *SwitchMux) (*peer_handler, error) {
	hashname, err := HashnameFromPublicKey(&prvkey.PublicKey)
	if err != nil {
		return nil, err
	}

	h := &peer_handler{
		local_hashname: hashname,
		peers:          make(map[Hashname]*peer_t),
	}

	mux.handle_func("seek", h.serve_seek)
	mux.handle_func("peer", h.serve_peer)
	mux.handle_func("connect", h.serve_connect)

	return h, nil
}

func (h *peer_handler) get_local_hashname() Hashname {
	return h.local_hashname
}

func (h *peer_handler) add_peer(hashname Hashname, addr string, pubkey *rsa.PublicKey, via Hashname) (Hashname, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return ZeroHashname, err
	}

	if hashname.IsZero() {
		hashname, err = HashnameFromPublicKey(pubkey)
		if err != nil {
			return ZeroHashname, err
		}
	}

	h.peers_mtx.Lock()
	defer h.peers_mtx.Unlock()

	h.peers[hashname] = &peer_t{
		hashname: hashname,
		pubkey:   pubkey,
		addr:     udp_addr,
		via:      via,
	}

	return hashname, nil
}

func (h *peer_handler) remove_peer(hashname Hashname) {
	h.peers_mtx.Lock()
	defer h.peers_mtx.Unlock()

	delete(h.peers, hashname)
}

func (h *peer_handler) get_peer(hashname Hashname) *peer_t {
	h.peers_mtx.RLock()
	defer h.peers_mtx.RUnlock()

	return h.peers[hashname]
}

func (h *peer_handler) find_closest_hashnames(t Hashname, n int) []Hashname {
	h.peers_mtx.RLock()
	defer h.peers_mtx.RUnlock()

	hashnames := make([]Hashname, 0, len(h.peers))

	for hn := range h.peers {
		hashnames = append(hashnames, hn)
	}

	kad_sort_by_distance(h.local_hashname, hashnames)

	if len(hashnames) > n {
		hashnames = hashnames[:n]
	}

	return hashnames
}

func (h *peer_handler) seek(hashname Hashname, n int) []Hashname {
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

func (h *peer_handler) send_seek_cmd(to, seek Hashname, wg *sync.WaitGroup) {
	defer wg.Done()

	local_hashname := h.get_local_hashname()

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "seek",
			Seek: seek.String(),
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
			hashname_str = fields[0]
			ip           = fields[1]
			port         = fields[2]
			addr         = net.JoinHostPort(ip, port)
		)

		hashname, err := HashnameFromString(hashname_str)
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
			continue
		}

		if hashname == local_hashname {
			continue
		}

		_, err = h.add_peer(hashname, addr, nil, to)
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

	seek, err := HashnameFromString(pkt.hdr.Seek)
	if err != nil {
		Log.Debug(err)
	}

	closest := h.find_closest_hashnames(seek, 25)
	see := make([]string, 0, len(closest))

	for _, hashname := range closest {
		peer := h.get_peer(hashname)
		if peer == nil {
			continue
		}
		if peer.pubkey == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		line := h.conn.conn.get_snd_line(peer.hashname)
		if line == nil {
			continue
		}

		if !line.opened {
			continue
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

func (h *peer_handler) send_peer_cmd(hashname Hashname) error {
	to := h.get_peer(hashname)
	if to == nil {
		return fmt.Errorf("unknown peer: %s", hashname)
	}
	if to.via.IsZero() {
		return fmt.Errorf("peer has unknown via: %s", hashname)
	}

	via := h.get_peer(to.via)
	if via == nil {
		return fmt.Errorf("peer has unknown via: %s", hashname)
	}

	if to.addr != nil {
		h.conn.conn.conn.send(&pkt_t{
			hdr:  pkt_hdr_t{Type: "+ping"},
			addr: to.addr,
		})
	}

	conn_ch, err := h.conn.open_channel(via.hashname, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "peer",
			Peer: to.hashname.String(),
			End:  true,
		},
	})
	defer conn_ch.close()
	return err
}

func (h *peer_handler) serve_peer(channel *channel_t) {
	pkt, err := channel.receive()
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	peer, err := HashnameFromString(pkt.hdr.Peer)
	if err != nil {
		Log.Debug(err)
	}

	if peer == h.get_local_hashname() {
		return
	}

	if peer == channel.peer {
		return
	}

	sender := h.get_peer(channel.peer)
	if sender == nil {
		return
	}

	pubkey, err := enc_DER_RSA(sender.pubkey)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	conn_ch, err := h.conn.open_channel(peer, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "connect",
			IP:   sender.addr.IP.String(),
			Port: sender.addr.Port,
			End:  true,
		},
		body: pubkey,
	})
	conn_ch.close()

	if err != nil {
		channel.close_with_error(err.Error())
	}
}

func (h *peer_handler) serve_connect(channel *channel_t) {
	pkt, err := channel.receive()
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	addr := net.JoinHostPort(pkt.hdr.IP, strconv.Itoa(pkt.hdr.Port))

	pubkey, err := dec_DER_RSA(pkt.body)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	hashname, err := h.add_peer(ZeroHashname, addr, pubkey, ZeroHashname)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	Log.Debugf("(l=%s) hashname=%s addr=%+q", h.get_local_hashname().Short(), hashname.Short(), addr)

	err = h.conn.conn.open_line(hashname)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}
}

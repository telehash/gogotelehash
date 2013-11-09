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

type peer_controller struct {
	sw             *Switch
	local_hashname Hashname
	buckets        [][]*peer_t
	peers_mtx      sync.RWMutex
}

func peer_controller_open(sw *Switch, mux *SwitchMux) (*peer_controller, error) {
	hashname, err := HashnameFromPublicKey(&sw.key.PublicKey)
	if err != nil {
		return nil, err
	}

	h := &peer_controller{
		sw:             sw,
		local_hashname: hashname,
		buckets:        make([][]*peer_t, 32*8),
	}

	mux.handle_func("seek", h.serve_seek)
	mux.handle_func("peer", h.serve_peer)
	mux.handle_func("connect", h.serve_connect)

	return h, nil
}

func (h *peer_controller) get_local_hashname() Hashname {
	return h.local_hashname
}

func (h *peer_controller) add_peer(hashname Hashname, addr string, pubkey *rsa.PublicKey, via Hashname) (Hashname, error) {
	var (
		err      error
		udp_addr *net.UDPAddr
		peer     *peer_t
	)

	// resolve the address
	udp_addr, err = net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return ZeroHashname, err
	}

	// determine the hashname
	if hashname.IsZero() {
		if pubkey == nil {
			return ZeroHashname, fmt.Errorf("pubkey must not be nil")
		}

		hashname, err = HashnameFromPublicKey(pubkey)
		if err != nil {
			return ZeroHashname, err
		}
	}

	peer = h.get_peer(hashname)

	if peer == nil {
		// make new peer
		peer = &peer_t{
			hashname: hashname,
			via:      via,
		}

		bucket := kad_bucket_for(h.get_local_hashname(), hashname)

		// add the peer
		h.peers_mtx.Lock()
		l := h.buckets[bucket]
		l = append(l, peer)
		h.buckets[bucket] = l
		h.peers_mtx.Unlock()
	}

	peer.addr = udp_addr

	if pubkey != nil {
		peer.pubkey = pubkey
	}

	if !via.IsZero() {
		peer.via = via
	}

	return hashname, nil
}

func (h *peer_controller) get_peer(hashname Hashname) *peer_t {
	bucket_index := kad_bucket_for(h.get_local_hashname(), hashname)

	if bucket_index < 0 {
		return nil
	}

	h.peers_mtx.RLock()
	bucket := h.buckets[bucket_index]
	h.peers_mtx.RUnlock()

	for _, peer := range bucket {
		if peer.hashname == hashname {
			return peer
		}
	}

	return nil
}

func (h *peer_controller) find_closest_peers(t Hashname, n int) []*peer_t {
	bucket_index := kad_bucket_for(h.get_local_hashname(), t)
	delta := 0

	if bucket_index < 0 {
		return nil
	}

	var (
		peers = make([]*peer_t, 0, 10)
	)

	for len(peers) < n {
		if 0 <= bucket_index+delta && bucket_index+delta < 32*8 {
			h.peers_mtx.RLock()
			bucket := h.buckets[bucket_index+delta]
			h.peers_mtx.RUnlock()
			peers = append(peers, bucket...)
		}

		if delta <= 0 {
			delta = -delta + 1
		} else {
			delta = -delta
		}

		if delta >= 32*8 {
			break
		}
	}

	kad_sort_peers(t, peers)

	if len(peers) > n {
		peers = peers[:n]
	}

	return peers
}

func (h *peer_controller) seek(hashname Hashname, n int) []*peer_t {
	var (
		wg   sync.WaitGroup
		last = h.find_closest_peers(hashname, n)
	)

	tag := time.Now().UnixNano()

	Log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last)

RECURSOR:
	for {

		Log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last)
		for _, via := range last {
			wg.Add(1)
			go h.send_seek_cmd(via.hashname, hashname, &wg)
		}

		wg.Wait()

		curr := h.find_closest_peers(hashname, n)
		Log.Debugf("%d => %s seek(%s):\n  %+v\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last, curr)

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

func (h *peer_controller) send_seek_cmd(to, seek Hashname, wg *sync.WaitGroup) {
	defer wg.Done()

	local_hashname := h.get_local_hashname()

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "seek",
			Seek: seek.String(),
		},
	}

	channel, err := h.sw.channels.open_channel(to, pkt)
	if err != nil {
		Log.Debugf("failed to seek %s (error: %s)", to, err)
		return
	}
	// defer channel.close()

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

func (h *peer_controller) serve_seek(channel *channel_t) {
	pkt, err := channel.receive()
	if err != nil {
		return // drop
	}

	seek, err := HashnameFromString(pkt.hdr.Seek)
	if err != nil {
		Log.Debug(err)
	}

	closest := h.find_closest_peers(seek, 25)
	see := make([]string, 0, len(closest))

	for _, peer := range closest {
		if peer.pubkey == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		if !h.sw.channels.conn.has_open_line_to(peer.hashname) {
			continue
		}

		see = append(see, fmt.Sprintf("%s,%s,%d", peer.hashname, peer.addr.IP, peer.addr.Port))
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

func (h *peer_controller) send_peer_cmd(hashname Hashname) error {
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
		h.sw.net.Send(hashname, &pkt_t{
			hdr:  pkt_hdr_t{Type: "+ping"},
			addr: to.addr,
		})
	}

	conn_ch, err := h.sw.channels.open_channel(via.hashname, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "peer",
			Peer: to.hashname.String(),
			End:  true,
		},
	})
	defer conn_ch.close()
	return err
}

func (h *peer_controller) serve_peer(channel *channel_t) {
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

	conn_ch, err := h.sw.channels.open_channel(peer, &pkt_t{
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

func (h *peer_controller) serve_connect(channel *channel_t) {
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

	err = h.sw.channels.conn._snd_open_pkt(hashname)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}
}

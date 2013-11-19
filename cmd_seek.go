package telehash

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func (h *peer_controller) seek(hashname Hashname, n int) []*peer_t {
	var (
		wg    sync.WaitGroup
		last  = h.find_closest_peers(hashname, n)
		cache = map[Hashname]bool{}
	)

	tag := time.Now().UnixNano()

	h.log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last)

RECURSOR:
	for {

		h.log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last)
		for _, via := range last {
			if cache[via.addr.hashname] {
				continue
			}

			cache[via.addr.hashname] = true

			wg.Add(1)
			go h.send_seek_cmd(via, hashname, &wg)
		}

		wg.Wait()

		curr := h.find_closest_peers(hashname, n)
		h.log.Debugf("%d => %s seek(%s):\n  %+v\n  %+v", tag, h.get_local_hashname().Short(), hashname.Short(), last, curr)

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

func (h *peer_controller) send_seek_cmd(via *peer_t, seek Hashname, wg *sync.WaitGroup) {
	defer wg.Done()
	via.send_seek_cmd(seek)
}

func (peer *peer_t) send_seek_cmd(seek Hashname) {
	local_hashname := peer.sw.peers.get_local_hashname()

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "seek",
			Seek: seek.String(),
		},
	}

	channel, err := peer.open_channel(pkt, true)
	if err != nil {
		return
	}

	defer channel.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true, Err: "timeout"}})

	channel.set_rcv_deadline(time.Now().Add(15 * time.Second))

	reply, err := channel.pop_rcv_pkt()
	if err != nil {
		Log.Debugf("failed to seek %s (error: %s)", peer.addr, err)
		return
	}

	peer.log.Infof("rcv seek: see=%+v", reply.hdr.See)

	for _, rec := range reply.hdr.See {
		fields := strings.Split(rec, ",")

		if len(fields) != 3 {
			continue
		}

		var (
			hashname_str = fields[0]
			ip           = fields[1]
			port         = fields[2]
			addr_str     = net.JoinHostPort(ip, port)
		)

		hashname, err := HashnameFromString(hashname_str)
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
			continue
		}

		if hashname == local_hashname {
			continue
		}

		addr, err := make_addr(hashname, peer.addr.hashname, addr_str, nil)
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
		}

		peer, discovered := peer.sw.peers.add_peer(addr)
		if discovered {
			peer.log.Infof("seek: discoverd peer addr=%s", addr)
			go peer.send_seek_cmd(peer.sw.LocalHashname())
		}
	}
}

func (h *peer_controller) serve_seek(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
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
		if peer.addr.pubkey == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		if !peer.IsGood() {
			continue
		}

		see = append(see, fmt.Sprintf("%s,%s,%d",
			peer.addr.hashname,
			peer.addr.addr.IP,
			peer.addr.addr.Port,
		))
	}

	h.log.Infof("rcv seek: see=%+v closest=%+v", see, closest)

	err = channel.snd_pkt(&pkt_t{
		hdr: pkt_hdr_t{
			See: see,
			End: true,
		},
	})
	if err != nil {
		return
	}
}

package telehash

import (
	"fmt"
	"github.com/fd/go-util/log"
	"net"
	"strings"
	"sync"
	"time"
)

type seek_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *seek_handler) init_seek_handler(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "seek-handler")

	sw.mux.handle_func("seek", h.serve_seek)
}

func (h *seek_handler) Seek(via, seek Hashname) error {
	h.log.Infof("seeking=%s via=%s", seek.Short(), via.Short())

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "seek",
			Seek: seek.String(),
		},
	}

	channel, err := h.sw.main.OpenChannel(via, pkt, true)
	if err != nil {
		return err
	}

	defer channel.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true, Err: "timeout"}})

	channel.set_rcv_deadline(time.Now().Add(15 * time.Second))

	reply, err := channel.pop_rcv_pkt()
	if err != nil {
		Log.Debugf("failed to send seek to %s (error: %s)", via.Short(), err)
		return err
	}

	h.log.Infof("rcv seek: see=%+v", reply.hdr.See)

	for _, rec := range reply.hdr.See {
		fields := strings.Split(rec, ",")

		if len(fields) != 3 {
			continue
		}

		var (
			hashname_str = fields[0]
			ip_str       = fields[1]
			port_str     = fields[2]
		)

		hashname, err := HashnameFromString(hashname_str)
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
			continue
		}

		netpath, err := ParseIPNetPath(net.JoinHostPort(ip_str, port_str))
		if err != nil {
			h.log.Debugf("error: %s", "invalid address")
			continue
		}

		if hashname == h.sw.hashname {
			// add address to main
			// detect nat
			continue // is self
		}

		if hashname == via {
			continue
		}

		peer, _ := h.sw.main.AddPeer(hashname)

		peer.AddVia(via)

		peer.AddNetPath(netpath)

		h.sw.main.GetLine(peer.Hashname())
	}

	return nil
}

func (h *seek_handler) RecusiveSeek(hashname Hashname, n int) []*Peer {
	var (
		wg    sync.WaitGroup
		last  = h.sw.main.GetClosestPeers(hashname, n)
		cache = map[Hashname]bool{}
	)

	tag := time.Now().UnixNano()

	h.log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.sw.hashname.Short(), hashname.Short(), last)

RECURSOR:
	for {

		h.log.Debugf("%d => %s seek(%s):\n  %+v", tag, h.sw.hashname.Short(), hashname.Short(), last)
		for _, via := range last {
			if cache[via.Hashname()] {
				continue
			}

			cache[via.Hashname()] = true

			if via.Hashname() == hashname {
				continue
			}

			wg.Add(1)
			go h.send_seek_cmd(via.Hashname(), hashname, &wg)
		}

		wg.Wait()

		curr := h.sw.main.GetClosestPeers(hashname, n)
		h.log.Debugf("%d => %s seek(%s):\n  %+v\n  %+v", tag, h.sw.hashname.Short(), hashname.Short(), last, curr)

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

func (h *seek_handler) send_seek_cmd(via, seek Hashname, wg *sync.WaitGroup) {
	defer wg.Done()
	h.Seek(via, seek)
}

func (h *seek_handler) serve_seek(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		return // drop
	}

	seek, err := HashnameFromString(pkt.hdr.Seek)
	if err != nil {
		Log.Debug(err)
	}

	closest := h.sw.main.GetClosestPeers(seek, 25)
	see := make([]string, 0, len(closest))

	for _, peer := range closest {
		if peer.PublicKey() == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		line := h.sw.main.GetLine(peer.Hashname())
		if line == nil {
			continue
		}

		if !line.State().test(line_opened, 0) {
			continue
		}

		for _, np := range peer.NetPaths() {
			if ip, port, ok := np.AddressForSeek(); ok {
				see = append(see, fmt.Sprintf("%s,%s,%d", peer.Hashname(), ip, port))
			}
		}
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

package telehash

import (
	"fmt"
	"github.com/fd/go-util/log"
	"strings"
	"sync"
	"time"
)

type seek_handler struct {
	sw  *Switch
	log log.Logger
}

type seek_header struct {
	Seek string   `json:"seek,omitempty"`
	See  []string `json:"see,omitempty"`
	end  bool
}

func (hdr *seek_header) End() bool { return hdr.end }

func (h *seek_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "seek-handler")

	sw.mux.HandleFunc("seek", h.serve_seek)
}

func (h *seek_handler) Seek(via, seek Hashname) error {
	var (
		req_header seek_header
		res_header seek_header
	)

	h.log.Debugf("seeking=%s via=%s", seek.Short(), via.Short())

	req_header.Seek = seek.String()

	options := ChannelOptions{To: via, Type: "seek", Reliablility: UnreliableChannel}
	channel, err := h.sw.Open(options)
	if err != nil {
		return err
	}
	defer channel.Close()

	_, err = channel.SendPacket(&req_header, nil)
	if err != nil {
		return err
	}

	channel.SetReceiveDeadline(time.Now().Add(15 * time.Second))

	_, err = channel.ReceivePacket(&res_header, nil)
	if err != nil {
		Log.Debugf("failed to send seek to %s (error: %s)", via.Short(), err)
		return err
	}

	h.log.Debugf("rcv seek: see=%+v", res_header.See)

	for _, rec := range res_header.See {
		fields := strings.Split(rec, ",")

		hashname, err := HashnameFromString(fields[0])
		if err != nil {
			Log.Debugf("failed to add peer %s (error: %s)", hashname, err)
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

		peer, new_peer := h.sw.add_peer(hashname)
		peer.AddVia(via)

		if len(fields) > 1 {
			np := h.parse_address(fields[1:])
			if np != nil {
				peer.add_net_path(np)
			}
		}

		if new_peer {
			peer.set_active_paths(peer.net_paths())
			go h.Seek(peer.hashname, h.sw.hashname)
		}
	}

	return nil
}

func (h *seek_handler) parse_address(fields []string) *net_path {
	for _, t := range h.sw.Transports {
		addr, ok := t.ParseSeekAddress(fields)
		if ok && addr != nil {
			return &net_path{Network: t.Network(), Address: addr}
		}
	}
	return nil
}

func (h *seek_handler) RecusiveSeek(hashname Hashname, n int) []*Peer {
	var (
		wg    sync.WaitGroup
		last  = h.sw.get_closest_peers(hashname, n)
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

		curr := h.sw.get_closest_peers(hashname, n)
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

func (h *seek_handler) serve_seek(channel *Channel) {
	var (
		req_header seek_header
		res_header seek_header
	)

	_, err := channel.ReceivePacket(&req_header, nil)
	if err != nil {
		return // drop
	}

	seek, err := HashnameFromString(req_header.Seek)
	if err != nil {
		Log.Debug(err)
	}

	closest := h.sw.get_closest_peers(seek, 25)
	see := make([]string, 0, len(closest))

	for _, peer := range closest {
		added := false

		if peer.PublicKey() == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		line := h.sw.get_active_line(peer.Hashname())
		if line == nil {
			continue
		}

		h.log.Debugf("netpaths for %s: %+v", peer, peer.net_paths())
	FOR_NETPATHS:
		for _, np := range peer.net_paths() {
			if np.Address.PublishWithSeek() {
				t := h.sw.transports[np.Network]
				if t == nil {
					continue
				}

				s := t.FormatSeekAddress(np.Address)
				if s != "" {
					added = true
					see = append(see, fmt.Sprintf("%s,%s", peer.Hashname(), s))
					break FOR_NETPATHS
				}
			}
		}

		if !added {
			see = append(see, peer.Hashname().String())
		}
	}

	h.log.Debugf("rcv seek: see=%+v closest=%+v", see, closest)

	res_header.See = see
	res_header.end = true

	_, err = channel.SendPacket(&res_header, nil)
	if err != nil {
		return
	}
}

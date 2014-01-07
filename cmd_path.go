package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
	"time"
)

const _PATH_DEADLINE = 10 * time.Second

type path_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *path_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "path-handler")

	sw.mux.HandleFunc("path", h.serve_path)
}

func (h *path_handler) Negotiate(to Hashname) bool {
	var (
		wg       sync.WaitGroup
		peer     *Peer
		netpaths NetPaths
		active   NetPaths
		relays   NetPaths
		results  []bool
		score    int
	)

	peer = h.sw.main.GetPeer(to)
	if peer == nil {
		return false
	}

	netpaths = peer.NetPaths()
	active = make(NetPaths, 0, len(netpaths))
	results = make([]bool, len(netpaths))
	relays = make(NetPaths, len(netpaths))

	for i, np := range netpaths {
		if _, ok := np.(*relay_net_path); ok {
			relays[i] = np
			continue
		}

		wg.Add(1)
		go func(np NetPath, wg *sync.WaitGroup, i int) {
			defer wg.Done()
			ok := h.negotiate_netpath(to, np)
			results[i] = ok
			if ok {
				np.ResetPriority()
			} else {
				np.Break()
			}
		}(np, &wg, i)
	}

	wg.Wait()

	for _, ok := range results {
		if ok {
			score++
		}
	}

	if score > 0 {
		for _, np := range relays {
			if np != nil {
				np.Demote()
			}
		}
	} else {
		for i, np := range relays {
			if np != nil {
				wg.Add(1)
				go func(np NetPath, wg *sync.WaitGroup, i int) {
					defer wg.Done()
					ok := h.negotiate_netpath(to, np)
					results[i] = ok
					if ok {
						np.ResetPriority()
					} else {
						np.Break()
					}
				}(np, &wg, i)
			}
		}

		wg.Wait()
	}

	score = 0
	for i, ok := range results {
		if ok {
			score++
			active = append(active, netpaths[i])
		}
	}

	peer.set_active_paths(active)

	return score > 0
}

func (h *path_handler) negotiate_netpath(to Hashname, netpath NetPath) bool {
	var (
		priority int
		pkt      *pkt_t
		channel  *Channel
		err      error
		latency  time.Duration
		now      = time.Now()
	)

	priority = netpath.Priority()
	if priority < 0 {
		priority = 0
	}

	paths, err := get_network_paths(h.sw.net.GetPort())
	if err != nil {
		paths = nil
	}

	pkt = &pkt_t{
		hdr: pkt_hdr_t{
			Priority: priority,
			Paths:    paths,
		},
		netpath: netpath,
	}

	options := ChannelOptions{To: to, Type: "path", Reliablility: UnreliableChannel}
	channel, err = h.sw.main.OpenChannel(options)
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	err = channel.send_packet(pkt)
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	channel.SetReceiveDeadline(now.Add(_PATH_DEADLINE))

	pkt, err = channel.receive_packet()
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	if priority > pkt.hdr.Priority {
		priority = pkt.hdr.Priority
		// TODO adjust priority
	}

	latency = time.Now().Sub(now)
	// TODO record latency

	h.log.Noticef("path: to=%s netpath=%s priority=%d latency=%s send-paths=%s", to.Short(), netpath, priority, latency, paths)
	return true
}

func (h *path_handler) serve_path(channel *Channel) {
	pkt, err := channel.receive_packet()
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.To().Short(), err)
	}

	priority := pkt.netpath.Priority()
	if pkt.hdr.Priority < priority {
		priority = pkt.hdr.Priority
	}

	err = channel.send_packet(&pkt_t{
		hdr: pkt_hdr_t{
			End:      true,
			Priority: priority,
		},
		netpath: pkt.netpath,
	})
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.To().Short(), err)
	}

	for _, np := range pkt.hdr.Paths {
		pkt.peer.AddNetPath(np)
	}
}

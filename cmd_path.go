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

	sw.mux.handle_func("path", h.serve_path)
}

func (h *path_handler) Negotiate(to Hashname) bool {
	var (
		wg       sync.WaitGroup
		peer     *Peer
		netpaths []NetPath
		results  chan bool
	)

	peer = h.sw.main.GetPeer(to)
	if peer == nil {
		return false
	}

	netpaths = peer.NetPaths()
	results = make(chan bool, len(netpaths))

	for _, np := range netpaths {
		wg.Add(1)
		go func(np NetPath) {
			defer wg.Done()
			results <- h.negotiate_netpath(to, np)
		}(np)
	}

	wg.Wait()
	close(results)

	for ok := range results {
		if ok {
			return true
		}
	}

	return false
}

func (h *path_handler) negotiate_netpath(to Hashname, netpath NetPath) bool {
	var (
		priority int
		pkt      *pkt_t
		channel  *channel_t
		err      error
		latency  time.Duration
		now      = time.Now()
	)

	priority = netpath.Priority()
	if priority < 0 {
		priority = 0
	}

	pkt = &pkt_t{
		hdr: pkt_hdr_t{
			Type:     "path",
			Priority: priority,
		},
		netpath: netpath,
	}

	channel, err = h.sw.main.OpenChannel(to, pkt, true)
	if err != nil {
		h.log.Noticef("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	channel.set_rcv_deadline(now.Add(_PATH_DEADLINE))

	pkt, err = channel.pop_rcv_pkt()
	if err != nil {
		h.log.Noticef("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	if priority > pkt.hdr.Priority {
		priority = pkt.hdr.Priority
		// TODO adjust priority
	}

	latency = time.Now().Sub(now)
	// TODO record latency

	h.log.Noticef("path: to=%s netpath=%s priority=%d latency=%s", to.Short(), netpath, priority, latency)
	return true
}

func (h *path_handler) serve_path(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.line.peer, err)
	}

	priority := pkt.netpath.Priority()
	if pkt.hdr.Priority < priority {
		priority = pkt.hdr.Priority
	}

	err = channel.snd_pkt(&pkt_t{
		hdr: pkt_hdr_t{
			End:      true,
			Priority: priority,
		},
		netpath: pkt.netpath,
	})
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.line.peer, err)
	}
}

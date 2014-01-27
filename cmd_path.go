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

type path_header struct {
	Paths    raw_net_paths `json:"paths,omitempty"`
	Priority int           `json:"priority,omitempty"`
	netpath  *net_path
	end      bool
}

func (hdr *path_header) End() bool                { return hdr.end }
func (hdr *path_header) get_net_path() *net_path  { return hdr.netpath }
func (hdr *path_header) set_net_path(n *net_path) { hdr.netpath = n }

func (h *path_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "path-handler")

	sw.mux.HandleFunc("path", h.serve_path)
}

func (h *path_handler) Negotiate(to Hashname) bool {
	var (
		wg       sync.WaitGroup
		peer     *Peer
		netpaths net_paths
		active   net_paths
		relays   net_paths
		results  []bool
		score    int
	)

	peer = h.sw.GetPeer(to, false)
	if peer == nil {
		return false
	}

	netpaths = peer.net_paths()
	active = make(net_paths, 0, len(netpaths))
	results = make([]bool, len(netpaths))
	relays = make(net_paths, len(netpaths))

	for i, np := range netpaths {
		if np.Network == "relay" {
			relays[i] = np
			continue
		}

		wg.Add(1)
		go func(np *net_path, wg *sync.WaitGroup, i int) {
			defer wg.Done()
			ok := h.negotiate_netpath(to, np)
			results[i] = ok
			if ok {
				np.ResetPriority()
			} else {
				peer.remove_net_path(np)
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
				peer.remove_net_path(np)
			}
		}
	} else {
		for i, np := range relays {
			if np != nil {
				wg.Add(1)
				go func(np *net_path, wg *sync.WaitGroup, i int) {
					defer wg.Done()
					ok := h.negotiate_netpath(to, np)
					results[i] = ok
					if ok {
						np.ResetPriority()
					} else {
						peer.remove_net_path(np)
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

func (h *path_handler) negotiate_netpath(to Hashname, netpath *net_path) bool {
	var (
		priority int
		channel  *Channel
		err      error
		latency  time.Duration
		now      = time.Now()
	)

	priority = netpath.Priority()
	if priority < 0 {
		priority = 0
	}

	paths := h.sw.get_network_paths()
	raw_paths, err := encode_net_paths(paths)
	if err != nil {
		raw_paths = nil
	}

	header := path_header{
		Paths:    raw_paths,
		Priority: priority,
		netpath:  netpath,
	}

	options := ChannelOptions{to: to, Type: "path", Reliablility: UnreliableChannel}
	channel, err = h.sw.open_channel(options)
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}
	defer channel.Close()

	_, err = channel.SendPacket(&header, nil)
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	channel.SetReceiveDeadline(now.Add(_PATH_DEADLINE))

	_, err = channel.ReceivePacket(&header, nil)
	if err != nil {
		h.log.Debugf("failed: to=%s netpath=%s err=%s", to.Short(), netpath, err)
		return false
	}

	if priority > header.Priority {
		priority = header.Priority
		// TODO adjust priority
	}

	latency = time.Now().Sub(now)
	// TODO record latency

	h.log.Debugf("path: to=%s netpath=%s priority=%d latency=%s", to.Short(), netpath, priority, latency)
	return true
}

func (h *path_handler) serve_path(channel *Channel) {
	var (
		req_header path_header
		res_header path_header
	)

	_, err := channel.ReceivePacket(&req_header, nil)
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.To().Short(), err)
	}

	priority := req_header.netpath.Priority()
	if req_header.Priority < priority {
		priority = req_header.Priority
	}

	res_header = path_header{
		end:      true,
		netpath:  req_header.netpath,
		Priority: priority,
	}

	_, err = channel.SendPacket(&res_header, nil)
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.To().Short(), err)
	}

	paths, err := decode_net_paths(req_header.Paths)
	if err == nil {
		for _, np := range paths {
			channel.Peer().add_net_path(np)
		}
	}
}

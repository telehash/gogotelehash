package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
)

type main_controller struct {
	sw       *Switch
	log      log.Logger
	shutdown chan bool
	wg       sync.WaitGroup

	lines                map[Hashname]*line_t
	get_line_chan        chan cmd_line_get
	register_line_chan   chan *line_t
	unregister_line_chan chan *line_t

	active_lines         map[string]*line_t
	get_active_line_chan chan cmd_line_get_active
	activate_line_chan   chan *line_t
	deactivate_line_chan chan *line_t

	peers                  peer_table
	get_peer_chan          chan cmd_peer_get
	add_peer_chan          chan cmd_peer_add
	get_closest_peers_chan chan cmd_peer_get_closest
}

type (
	cmd_peer_get struct {
		hashname Hashname
		reply    chan *peer_t
	}

	cmd_peer_add struct {
		addr  addr_t
		reply chan cmd_peer_add_res
	}

	cmd_peer_add_res struct {
		peer       *peer_t
		discovered bool
	}

	cmd_peer_get_closest struct {
		hashname Hashname
		n        int
		reply    chan []*peer_t
	}

	cmd_line_get_active struct {
		id    string
		reply chan *line_t
	}

	cmd_line_get struct {
		hashname Hashname
		addr     addr_t
		pub      *public_line_key
		reply    chan *line_t
	}
)

func main_controller_open(sw *Switch) (*main_controller, error) {
	c := &main_controller{
		sw:       sw,
		log:      sw.log,
		shutdown: make(chan bool, 1),

		lines:                make(map[Hashname]*line_t),
		get_line_chan:        make(chan cmd_line_get),
		register_line_chan:   make(chan *line_t),
		unregister_line_chan: make(chan *line_t),

		active_lines:         make(map[string]*line_t),
		get_active_line_chan: make(chan cmd_line_get_active),
		activate_line_chan:   make(chan *line_t),
		deactivate_line_chan: make(chan *line_t),

		get_peer_chan:          make(chan cmd_peer_get),
		add_peer_chan:          make(chan cmd_peer_add),
		get_closest_peers_chan: make(chan cmd_peer_get_closest),
	}

	c.peers.Init(sw.hashname)

	c.wg.Add(1)
	go c._loop()

	return c, nil
}

func (c *main_controller) GetPeer(hashname Hashname) *peer_t {
	reply := make(chan *peer_t)
	c.get_peer_chan <- cmd_peer_get{hashname, reply}
	return <-reply
}

func (c *main_controller) GetClosestPeers(hashname Hashname, n int) []*peer_t {
	reply := make(chan []*peer_t)
	c.get_closest_peers_chan <- cmd_peer_get_closest{hashname, n, reply}
	return <-reply
}

func (c *main_controller) AddPeer(addr addr_t) (*peer_t, bool) {
	reply := make(chan cmd_peer_add_res)
	c.add_peer_chan <- cmd_peer_add{addr, reply}
	res := <-reply
	return res.peer, res.discovered
}

func (c *main_controller) OpenChannel(to Hashname, pkt *pkt_t, raw bool) (*channel_t, error) {
	reply := make(chan *line_t)
	c.get_line_chan <- cmd_line_get{to, addr_t{}, nil, reply}
	line := <-reply

	if line == nil {
		return nil, ErrUnknownPeer
	}

	return line.OpenChannel(pkt, raw)
}

func (c *main_controller) Close() {
	c.shutdown <- true
	c.wg.Wait()
}

func (c *main_controller) _loop() {
	var (
		terminating bool
	)

	defer c.wg.Done()

	for {
		select {

		case <-c.shutdown:
			terminating = true
			c.log.Noticef("shutdown lines=%d", len(c.lines))
			for _, l := range c.lines {
				l.Shutdown()
			}
			if len(c.lines) == 0 {
				return
			}

		case line := <-c.activate_line_chan:
			c.active_lines[line.prv_key.id] = line
		case line := <-c.deactivate_line_chan:
			delete(c.active_lines, line.prv_key.id)
		case cmd := <-c.get_active_line_chan:
			cmd.reply <- c.active_lines[cmd.id]

		case line := <-c.register_line_chan:
			c.lines[line.peer.addr.hashname] = line
		case line := <-c.unregister_line_chan:
			delete(c.lines, line.peer.addr.hashname)
			c.log.Noticef("removed line=%s lines=%d", line.peer, len(c.lines))
			if terminating {
				c.log.Noticef("shutdown lines=%d", len(c.lines))
			}
			if terminating && len(c.lines) == 0 {
				return
			}
		case cmd := <-c.get_line_chan:
			c.get_line(cmd)

		case cmd := <-c.get_peer_chan:
			cmd.reply <- c.peers.get_peer(cmd.hashname)
		case cmd := <-c.add_peer_chan:
			c.add_peer(cmd)
		case cmd := <-c.get_closest_peers_chan:
			cmd.reply <- c.peers.find_closest_peers(cmd.hashname, cmd.n)

		}
	}
}

func (c *main_controller) add_peer(cmd cmd_peer_add) {
	peer, disc := c.peers.add_peer(cmd.addr)

	if disc {
		c.log.Noticef("discovered: %s (add_peer)", peer)
		c.get_line(cmd_line_get{hashname: peer.addr.hashname})
	}

	cmd.reply <- cmd_peer_add_res{peer, disc}
}

func (c *main_controller) seek_discovered_peer(peer *peer_t) {
	err := c.sw.seek_handler.Seek(peer.addr.hashname, c.sw.hashname)
	if err != nil {
		c.log.Noticef("failed to seek: %s err=%s", peer.addr.hashname.Short(), err)
	}
}

func (c *main_controller) get_line(cmd cmd_line_get) {
	line := c.lines[cmd.hashname]

	if line == nil {
		addr := addr_t{hashname: cmd.hashname}
		if cmd.pub != nil {
			addr.pubkey = cmd.pub.rsa_pubkey
		}
		addr.update(cmd.addr)
		peer, disc := c.peers.add_peer(addr)
		addr = peer.addr

		if disc {
			c.log.Noticef("discovered: %s (get_line)", peer)
		}

		if (addr.pubkey != nil || !addr.via.IsZero()) && addr.addr != nil {
			line = &line_t{}
			line.Init(c.sw, peer)
			line.EnsureRunning()

			c.lines[cmd.hashname] = line
		}
	}

	if cmd.reply != nil {
		cmd.reply <- line
	}
}

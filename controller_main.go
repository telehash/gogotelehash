package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
	"sync/atomic"
	"time"
)

type main_controller struct {
	sw    *Switch
	log   log.Logger
	wg    sync.WaitGroup
	state main_state

	peers        peer_table
	lines        map[Hashname]*line_t
	active_lines map[string]*line_t

	num_open_lines    int32
	num_running_lines int32
}

func main_controller_open(sw *Switch) (*main_controller, error) {
	c := &main_controller{
		sw:           sw,
		log:          sw.log,
		lines:        make(map[Hashname]*line_t),
		active_lines: make(map[string]*line_t),
	}

	c.peers.Init(sw.hashname)

	c.wg.Add(1)
	c.state.mod(main_running, 0)
	go c.run_main_loop()

	return c, nil
}

// atomically get the main state
func (c *main_controller) State() main_state {
	return main_state(atomic.LoadUint32((*uint32)(&c.state)))
}

func (c *main_controller) GetPeer(hashname Hashname) *Peer {
	cmd := cmd_peer_get{hashname, nil}
	c.sw.reactor.Call(&cmd)
	return cmd.peer
}

func (c *main_controller) GetClosestPeers(hashname Hashname, n int) []*Peer {
	cmd := cmd_peer_get_closest{hashname, n, nil}
	c.sw.reactor.Call(&cmd)
	return cmd.peers
}

func (c *main_controller) AddPeer(hashname Hashname) (*Peer, bool) {
	cmd := cmd_peer_add{hashname, nil, false}
	c.sw.reactor.Call(&cmd)
	return cmd.peer, cmd.discovered
}

func (c *main_controller) OpenChannel(options ChannelOptions) (*Channel, error) {
	cmd := cmd_channel_open{options, nil, nil}
	c.sw.reactor.Call(&cmd)
	return cmd.channel, cmd.err
}

func (c *main_controller) PopulateStats(s *SwitchStats) {
	s.NumOpenLines += int(atomic.LoadInt32(&c.num_open_lines))
	s.NumRunningLines += int(atomic.LoadInt32(&c.num_running_lines))
	s.KnownPeers = int(atomic.LoadUint32(&c.peers.num_peers))
}

func (c *main_controller) GetLine(to Hashname) *line_t {
	cmd := cmd_line_get{to, nil}
	c.sw.reactor.Call(&cmd)
	return cmd.line
}

func (c *main_controller) GetActiveLine(to Hashname) *line_t {
	line := c.GetLine(to)
	if line != nil && line.state == line_opened {
		return line
	}
	return nil
}

func (c *main_controller) Close() {
	c.sw.reactor.Cast(&cmd_shutdown{})
	c.wg.Wait()
}

func (c *main_controller) RcvPkt(pkt *pkt_t) error {
	cmd := cmd_rcv_pkt{pkt}
	c.sw.reactor.Cast(&cmd)
	return nil
}

func (c *main_controller) run_main_loop() {
	defer c.teardown()

	c.setup()
	c.run_active_loop()
}

func (c *main_controller) run_active_loop() {
	var (
		stats = time.NewTicker(5 * time.Second)
	)

	defer stats.Stop()

	for c.state.test(0, main_terminating) || len(c.lines) > 0 {
		select {

		case <-stats.C:
			c.sw.log.Noticef("stats: %s", c.sw.Stats())

		}
	}
}

func (c *main_controller) setup() {
	c.state.mod(main_running, 0)
}

func (c *main_controller) teardown() {
	c.sw.log.Noticef("stats: %s", c.sw.Stats())
	c.wg.Done()
}

type cmd_peer_get struct {
	hashname Hashname
	peer     *Peer
}

func (cmd *cmd_peer_get) Exec(sw *Switch) {
	cmd.peer = sw.main.peers.get_peer(cmd.hashname)
}

type cmd_peer_add struct {
	hashname   Hashname
	peer       *Peer
	discovered bool
}

func (cmd *cmd_peer_add) Exec(sw *Switch) {
	cmd.peer, cmd.discovered = sw.main.peers.add_peer(sw, cmd.hashname)

	if cmd.discovered {
		sw.main.log.Noticef("discovered: %s (add_peer)", cmd.peer)
	}

}

type cmd_peer_get_closest struct {
	hashname Hashname
	n        int
	peers    []*Peer
}

func (cmd *cmd_peer_get_closest) Exec(sw *Switch) {
	cmd.peers = sw.main.peers.find_closest_peers(cmd.hashname, cmd.n)
}

type cmd_line_get struct {
	hashname Hashname
	line     *line_t
}

func (cmd *cmd_line_get) Exec(sw *Switch) {
	cmd.line = sw.main.lines[cmd.hashname]
}

type cmd_shutdown struct {
}

func (cmd *cmd_shutdown) Exec(sw *Switch) {
	sw.main.state.mod(main_terminating, main_running)

	sw.main.log.Noticef("shutdown lines=%d", len(sw.main.lines))
}

type cmd_rcv_pkt struct {
	pkt *pkt_t
}

func (cmd *cmd_rcv_pkt) Exec(sw *Switch) {
	var (
		main = sw.main
		pkt  = cmd.pkt
	)

	if pkt.hdr.Type == "line" {
		line := main.active_lines[pkt.hdr.Line]

		if line == nil {
			main.log.Errorf("line: error: %s", errUnknownLine)
			return
		}

		cmd.rcv_line_pkt(line, pkt)
		return
	}

	if pkt.hdr.Type == "open" {
		pub, err := decompose_open_pkt(sw.key, pkt)
		if err != nil {
			main.log.Errorf("open: error: %s", err)
			return
		}

		peer, newpeer := main.peers.add_peer(sw, pub.hashname)
		peer.AddNetPath(pkt.netpath)
		peer.SetPublicKey(pub.rsa_pubkey)
		if newpeer {
			peer.set_active_paths(peer.NetPaths())
		}

		line := main.lines[peer.Hashname()]
		if line == nil {
			line = &line_t{}
			line.Init(sw, peer)
			main.lines[peer.Hashname()] = line
		}

		cmd.rcv_open_pkt(line, pub, pkt.netpath)
		return
	}

	// drop
	return
}

func (cmd *cmd_rcv_pkt) rcv_line_pkt(l *line_t, opkt *pkt_t) error {
	ipkt, err := l.shr_key.dec(opkt)
	if err != nil {
		return err
	}

	l.idle_timer.Reset(line_idle_timeout)
	l.broken_timer.Reset(line_broken_timeout)

	ipkt.peer = l.peer
	ipkt.netpath = opkt.netpath

	if ipkt.hdr.C != "" && ipkt.hdr.Type == "relay" {
		l.sw.relay_handler.rcv(ipkt)
		return nil
	}

	if ipkt.hdr.C == "" {
		return errInvalidPkt
	}

	// send pkt to existing channel
	if channel := l.channels[ipkt.hdr.C]; channel != nil {
		l.peer.AddNetPath(ipkt.netpath)
		l.log.Debugf("rcv pkt: addr=%s hdr=%+v", l.peer, ipkt.hdr)
		return channel.push_rcv_pkt(ipkt)
	}

	// open new channel
	if ipkt.hdr.Type == "" {
		return errInvalidPkt
	}

	reliablility := ReliableChannel
	if !ipkt.hdr.Seq.IsSet() {
		reliablility = UnreliableChannel
	}

	if reliablility == ReliableChannel && ipkt.hdr.Seq.Get() != 0 {
		return errInvalidPkt
	}

	options := ChannelOptions{To: l.peer.hashname, Id: ipkt.hdr.C, Type: ipkt.hdr.Type, Reliablility: reliablility}
	channel, err := make_channel(l.sw, l, false, options)
	if err != nil {
		return err
	}

	l.channels[channel.Id()] = channel
	channel.line_state_changed()

	l.log.Debugf("rcv pkt: addr=%s hdr=%+v", l.peer, ipkt.hdr)

	l.log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.Id()),
		channel.Type(),
		l.sw.hashname.Short(),
		l.peer.Hashname().Short())

	err = channel.push_rcv_pkt(ipkt)
	if err != nil {
		return err
	}

	l.peer.AddNetPath(ipkt.netpath)
	go channel.run_user_handler()

	return nil
}

func (cmd *cmd_rcv_pkt) rcv_open_pkt(l *line_t, pub *public_line_key, netpath NetPath) error {
	var (
		err            error
		local_rsa_key  = l.sw.key
		local_hashname = l.sw.hashname
	)

	if l.state == line_opened {
		// reopen line?
		return nil // drop
	}

	prv := l.prv_key
	if prv == nil {
		err := l.SndOpen(netpath)
		if err != nil {
			return err
		}
		prv = l.prv_key
	}

	err = pub.verify(l.pub_key, local_hashname)
	if err != nil {
		l.log.Noticef("rcv open from=%s err=%s", netpath, err)
		return nil
	}

	shr, err := line_activate(prv, pub)
	if err != nil {
		l.log.Noticef("rcv open from=%s err=%s", netpath, err)
		return err
	}

	l.peer.SetPublicKey(pub.rsa_pubkey)
	l.peer.AddNetPath(netpath)

	l.log.Debugf("rcv open from=%s", l.peer)

	l.prv_key = prv
	l.pub_key = pub
	l.shr_key = shr

	l.state = line_opened
	l.open_timer.Stop()
	l.open_timer = nil
	l.path_timer = l.sw.reactor.CastAfter(line_path_interval, &cmd_line_snd_path{l})
	l.seek_timer = l.sw.reactor.CastAfter(line_path_interval, &cmd_line_snd_seek{l})
	l.broken_timer.Reset(line_broken_timeout)
	l.idle_timer.Reset(line_idle_timeout)
	l.sw.main.active_lines[l.prv_key.id] = l

	l.backlog.CatchUp(&l.sw.reactor)
	return nil
}

type cmd_snd_pkt struct {
	channel *Channel
	line    *line_t
	pkt     *pkt_t
	err     error
}

func (cmd *cmd_snd_pkt) Exec(sw *Switch) {
	var (
		channel = cmd.channel
		line    = cmd.line
		pkt     = cmd.pkt
		err     error
	)

	if channel != nil {
		defer_, err = channel.imp.will_send_packet(pkt)
		if err != nil {
			cmd.err = err
			return
		}
		if defer_ {
			sw.reactor.Defer(&channel.snd_backlog)
			return
		}
	}

	pkt.peer = line.peer

	pkt, err = line.shr_key.enc(pkt)
	if err != nil {
		cmd.err = err
		return
	}

	sender := pkt.netpath
	if sender == nil {
		sender = line.peer.ActivePath()
	}
	if sender == nil {
		cmd.err = ErrPeerBroken
		return
	}

	err = sender.Send(sw, pkt)
	if err != nil {
		cmd.err = err
		return
	}

	channel.imp.did_send_packet(pkt)
}

type cmd_channel_open struct {
	options ChannelOptions
	channel channel_i
	err     error
}

func (cmd *cmd_channel_open) Exec(sw *Switch) {
	var (
		line    *line_t
		channel channel_i
		err     error
	)

	if sw.main.State().test(main_terminating, 0) {
		cmd.err = errNoOpenLine
		return
	}

	line = sw.main.lines[cmd.options.To]
	if line == nil {
		err = cmd.open_line(sw)
		if err != nil {
			cmd.err = err
		}
		return
	}
	if line.state != line_opened {
		sw.reactor.Defer(&line.backlog)
		return
	}

	channel, err = make_channel(sw, line, true, cmd.options)
	if err != nil {
		cmd.err = err
		return
	}

	line.channels[channel.Id()] = channel
	channel.line_state_changed()

	line.log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.Id()),
		channel.Type(),
		sw.hashname.Short(),
		line.peer.Hashname().Short())

	cmd.channel = channel
}

func (cmd *cmd_channel_open) open_line(sw *Switch) error {
	var (
		main = sw.main
		peer *Peer
		line *line_t
		err  error
	)

	peer = main.peers.get_peer(cmd.options.To)

	if peer == nil {
		// seek
		return ErrUnknownPeer
	}

	if peer.is_down {
		return ErrPeerBroken
	}

	if !peer.CanOpen() {
		return ErrPeerBroken
	}

	line = &line_t{}
	line.Init(sw, peer)
	err = cmd.open(line, peer)
	if err != nil {
		return err
	}

	main.lines[cmd.options.To] = line

	sw.reactor.Defer(&line.backlog)
	return nil
}

func (cmd *cmd_channel_open) open(l *line_t, peer *Peer) error {
	if len(peer.NetPaths()) == 0 && len(peer.via) != 0 {
		peer.AddNetPath(make_relay_net_path())
	}

	if peer.pubkey == nil && len(peer.via) != 0 {
		// start with sending a peer command
		l.state = line_peering
		go l.open_with_peer()
		return nil
	} else if peer.pubkey != nil && len(peer.paths) != 0 {
		// send open
		l.state = line_opening
		return l.SndOpen(nil)
	} else {
		// unreachable peer
		// TODO seek?
		return ErrPeerBroken
	}
}

type cmd_line_close_idle struct {
	line *line_t
}

func (cmd *cmd_line_close_idle) Exec(sw *Switch) {
	cmd.line.state = line_closed

	for _, c := range cmd.line.channels {
		c.line_state_changed()
	}

	cmd.line.broken_timer.Stop()
	cmd.line.idle_timer.Stop()
	cmd.line.path_timer.Stop()
	cmd.line.seek_timer.Stop()
	delete(sw.main.active_lines, cmd.line.prv_key.id)
	delete(sw.main.lines, cmd.line.peer.hashname)

	cmd.line.log.Noticef("line closed: peer=%s (reason=%s)",
		cmd.line.peer.String(),
		"idle")
}

type cmd_line_close_broken struct {
	line *line_t
}

func (cmd *cmd_line_close_broken) Exec(sw *Switch) {
	cmd.line.state = line_closed

	for _, c := range cmd.line.channels {
		c.line_state_changed()
	}

	cmd.line.broken_timer.Stop()
	cmd.line.idle_timer.Stop()
	cmd.line.path_timer.Stop()
	cmd.line.seek_timer.Stop()
	delete(sw.main.active_lines, cmd.line.prv_key.id)
	delete(sw.main.lines, cmd.line.peer.hashname)

	cmd.line.log.Noticef("line closed: peer=%s (reason=%s)",
		cmd.line.peer.String(),
		"broken")
}

type cmd_line_close_down struct {
	line *line_t
}

func (cmd *cmd_line_close_down) Exec(sw *Switch) {
	cmd.line.state = line_closed

	for _, c := range cmd.line.channels {
		c.line_state_changed()
	}

	cmd.line.broken_timer.Stop()
	cmd.line.idle_timer.Stop()
	cmd.line.path_timer.Stop()
	cmd.line.seek_timer.Stop()
	delete(sw.main.active_lines, cmd.line.prv_key.id)
	delete(sw.main.lines, cmd.line.peer.hashname)
}

type cmd_line_snd_path struct {
	line *line_t
}

func (cmd *cmd_line_snd_path) Exec(sw *Switch) {
	if cmd.line.state != line_opened {
		return
	}

	go func() {
		var (
			l = cmd.line
		)

		if sw.path_handler.Negotiate(l.peer.hashname) {
			l.path_timer.Reset(line_path_interval)
			return
		}

		func() {
			defer func() { recover() }()
			sw.reactor.Cast(&cmd_line_close_broken{l})
			l.log.Noticef("path failed (breaking the line)")
		}()
	}()
}

type cmd_line_snd_seek struct {
	line *line_t
}

func (cmd *cmd_line_snd_seek) Exec(sw *Switch) {
	if cmd.line.state != line_opened {
		return
	}

	go func() {
		var (
			l = cmd.line
		)

		err := sw.seek_handler.Seek(l.peer.Hashname(), sw.hashname)
		if err == nil {
			l.seek_timer.Reset(line_seek_interval)
			return
		}
		l.log.Noticef("seeking failed: err=%s", err)
	}()
}

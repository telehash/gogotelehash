package telehash

import (
	"time"
)

type cmd_peer_get struct {
	hashname Hashname
	peer     *Peer
}

func (cmd *cmd_peer_get) Exec(sw *Switch) {
	cmd.peer = sw.peers.get_peer(cmd.hashname)
}

type cmd_peer_add struct {
	hashname   Hashname
	peer       *Peer
	discovered bool
}

func (cmd *cmd_peer_add) Exec(sw *Switch) {
	cmd.peer, cmd.discovered = sw.peers.add_peer(sw, cmd.hashname)

	if cmd.discovered {
		sw.log.Noticef("discovered: %s (add_peer)", cmd.peer)
	}
}

type cmd_peer_get_closest struct {
	hashname Hashname
	n        int
	peers    []*Peer
}

func (cmd *cmd_peer_get_closest) Exec(sw *Switch) {
	cmd.peers = sw.peers.find_closest_peers(cmd.hashname, cmd.n)
}

type cmd_line_get struct {
	hashname Hashname
	line     *line_t
}

func (cmd *cmd_line_get) Exec(sw *Switch) {
	cmd.line = sw.lines[cmd.hashname]
}

type cmd_shutdown struct {
}

func (cmd *cmd_shutdown) Exec(sw *Switch) {
	sw.terminating = true

	sw.log.Noticef("shutdown lines=%d", len(sw.lines))

	for _, line := range sw.lines {
		sw.reactor.CastAfter(10*time.Second, &cmd_line_close_broken{line})
	}
}

type cmd_rcv_pkt struct {
	pkt *pkt_t
}

func (cmd *cmd_rcv_pkt) Exec(sw *Switch) {
	var (
		pkt = cmd.pkt
	)

	if pkt.hdr.Type == "line" {
		line := sw.active_lines[pkt.hdr.Line]

		if line == nil {
			sw.log.Errorf("line: error: %s", errUnknownLine)
			return
		}

		cmd.rcv_line_pkt(line, pkt)
		return
	}

	if pkt.hdr.Type == "open" {
		pub, err := decompose_open_pkt(sw.key, pkt)
		if err != nil {
			sw.log.Errorf("open: error: %s", err)
			return
		}

		peer, newpeer := sw.peers.add_peer(sw, pub.hashname)
		peer.AddNetPath(pkt.netpath)
		peer.SetPublicKey(pub.rsa_pubkey)
		if newpeer {
			peer.set_active_paths(peer.NetPaths())
		}

		line := sw.lines[peer.Hashname()]
		if line == nil {
			line = &line_t{}
			line.Init(sw, peer)
			sw.lines[peer.Hashname()] = line
			sw.num_running_lines += 1
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

	l.log.Debugf("rcv pkt: addr=%s hdr=%+v", l.peer, ipkt.hdr)

	l.log.Noticef("channel[%s:%s](%s -> %s): opened (initiator=false)",
		short_hash(channel.Id()),
		channel.Type(),
		l.peer.Hashname().Short(),
		l.sw.hashname.Short())

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
		err error
		// local_rsa_key  = l.sw.key
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

	l.prv_key = prv
	l.pub_key = pub
	l.shr_key = shr

	l.state = line_opened
	stop_timer(l.open_timer)
	l.open_timer = nil
	l.path_timer = l.sw.reactor.CastAfter(line_path_interval, &cmd_line_snd_path{l})
	l.seek_timer = l.sw.reactor.CastAfter(line_seek_interval, &cmd_line_snd_seek{l})
	l.broken_timer.Reset(line_broken_timeout)
	l.idle_timer.Reset(line_idle_timeout)
	l.sw.active_lines[l.prv_key.id] = l
	l.sw.num_open_lines += 1

	l.log.Debugf("line opened")

	l.backlog.RescheduleAll(&l.sw.reactor)
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
		ipkt    = cmd.pkt
		opkt    *pkt_t
		err     error
	)

	if channel != nil {
		if !channel.can_snd_pkt() {
			sw.reactor.Defer(&channel.snd_backlog)
			return
		}
		err = channel.will_send_packet(ipkt)
		if err != nil {
			cmd.err = err
			return
		}
	}

	ipkt.peer = line.peer

	opkt, err = line.shr_key.enc(ipkt)
	if err != nil {
		cmd.err = err
		return
	}

	sender := opkt.netpath
	if sender == nil {
		sender = line.peer.ActivePath()
	}
	if sender == nil {
		cmd.err = ErrPeerBroken
		return
	}

	err = sender.Send(sw, opkt)
	if err != nil {
		cmd.err = err
		return
	}

	if channel != nil {
		channel.did_send_packet(ipkt)
		channel.log.Debugf("snd pkt: hdr=%+v", ipkt.hdr)
	}

	line.log.Debugf("snd pkt: hdr=%+v", opkt.hdr)
}

type cmd_channel_open struct {
	options ChannelOptions
	channel *Channel
	err     error
}

func (cmd *cmd_channel_open) Exec(sw *Switch) {
	var (
		line    *line_t
		channel *Channel
		err     error
	)

	if sw.terminating {
		cmd.err = errNoOpenLine
		return
	}

	line = sw.lines[cmd.options.To]
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

	line.log.Noticef("channel[%s:%s](%s -> %s): opened (initiator=true)",
		short_hash(channel.Id()),
		channel.Type(),
		sw.hashname.Short(),
		line.peer.Hashname().Short())

	cmd.channel = channel
}

func (cmd *cmd_channel_open) open_line(sw *Switch) error {
	var (
		peer *Peer
		line *line_t
		err  error
	)

	peer = sw.peers.get_peer(cmd.options.To)

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

	sw.lines[cmd.options.To] = line
	sw.num_running_lines += 1

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
		c.mark_as_broken()
		c.reschedule()
	}

	stop_timer(cmd.line.open_timer)
	stop_timer(cmd.line.broken_timer)
	stop_timer(cmd.line.idle_timer)
	stop_timer(cmd.line.path_timer)
	stop_timer(cmd.line.seek_timer)

	if cmd.line.prv_key != nil {
		if _, p := sw.active_lines[cmd.line.prv_key.id]; p {
			sw.num_open_lines -= 1
			delete(sw.active_lines, cmd.line.prv_key.id)
		}
	}
	if cmd.line.peer != nil {
		if _, p := sw.lines[cmd.line.peer.hashname]; p {
			sw.num_running_lines -= 1
			delete(sw.lines, cmd.line.peer.hashname)
		}
	}

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
		c.mark_as_broken()
		c.reschedule()
	}

	stop_timer(cmd.line.open_timer)
	stop_timer(cmd.line.broken_timer)
	stop_timer(cmd.line.idle_timer)
	stop_timer(cmd.line.path_timer)
	stop_timer(cmd.line.seek_timer)

	if cmd.line.prv_key != nil {
		if _, p := sw.active_lines[cmd.line.prv_key.id]; p {
			sw.num_open_lines -= 1
			delete(sw.active_lines, cmd.line.prv_key.id)
		}
	}
	if cmd.line.peer != nil {
		if _, p := sw.lines[cmd.line.peer.hashname]; p {
			sw.num_running_lines -= 1
			delete(sw.lines, cmd.line.peer.hashname)
		}
	}

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
		c.mark_as_broken()
		c.reschedule()
	}

	stop_timer(cmd.line.open_timer)
	stop_timer(cmd.line.broken_timer)
	stop_timer(cmd.line.idle_timer)
	stop_timer(cmd.line.path_timer)
	stop_timer(cmd.line.seek_timer)

	if cmd.line.prv_key != nil {
		if _, p := sw.active_lines[cmd.line.prv_key.id]; p {
			sw.num_open_lines -= 1
			delete(sw.active_lines, cmd.line.prv_key.id)
		}
	}
	if cmd.line.peer != nil {
		if _, p := sw.lines[cmd.line.peer.hashname]; p {
			sw.num_running_lines -= 1
			delete(sw.lines, cmd.line.peer.hashname)
		}
	}

	cmd.line.log.Noticef("line closed: peer=%s (reason=%s)",
		cmd.line.peer.String(),
		"peer down")
}

type cmd_line_snd_path struct {
	line *line_t
}

func (cmd *cmd_line_snd_path) Exec(sw *Switch) {
	if sw.terminating {
		return
	}

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

type cmd_get_rcv_pkt struct {
	channel *Channel
	pkt     *pkt_t
	err     error
}

func (cmd *cmd_get_rcv_pkt) Exec(sw *Switch) {
	var (
		channel = cmd.channel
	)

	if !channel.can_pop_rcv_pkt() {
		sw.reactor.Defer(&channel.rcv_backlog)
		return
	}

	pkt, err := channel.pop_rcv_pkt()
	cmd.pkt = pkt
	cmd.err = err

	if err == nil && pkt == nil {
		sw.reactor.Defer(&channel.rcv_backlog)
	}
}

type cmd_channel_set_rcv_deadline struct {
	channel  *Channel
	deadline time.Time
}

func (cmd *cmd_channel_set_rcv_deadline) Exec(sw *Switch) {
	var (
		channel  = cmd.channel
		deadline = cmd.deadline
		now      = time.Now()
	)

	switch {

	case deadline.IsZero():
		// unset deadline
		channel.rcv_deadline_reached = false
		if channel.rcv_deadline != nil {
			stop_timer(channel.rcv_deadline)
		}

	case deadline.Before(now):
		// deadline reached (.deadline is in the past)
		channel.rcv_deadline_reached = true
		if channel.rcv_deadline != nil {
			stop_timer(channel.rcv_deadline)
		}
		channel.reschedule()

	default:
		// deadline scheduled (.deadline is in the future)
		channel.rcv_deadline_reached = false
		if channel.rcv_deadline != nil {
			channel.rcv_deadline.Reset(deadline.Sub(now))
		} else {
			sw.reactor.CastAfter(deadline.Sub(now), &cmd_channel_deadline_reached{channel})
		}

	}
}

type cmd_channel_deadline_reached struct {
	channel *Channel
}

func (cmd *cmd_channel_deadline_reached) Exec(sw *Switch) {
	var (
		channel = cmd.channel
	)

	channel.rcv_deadline_reached = true
	channel.reschedule()
}

type cmd_stats_log struct{}

func (cmd *cmd_stats_log) Exec(sw *Switch) {
	sw.log.Noticef("stats: %s", sw.Stats())
	sw.reactor.CastAfter(5*time.Second, cmd)
}

type cmd_clean struct{}

func (cmd *cmd_clean) Exec(sw *Switch) {
	for _, l := range sw.lines {
		for i, c := range l.channels {
			if c.is_closed() {
				l.log.Noticef("channel[%s:%s](%s -> %s): closed",
					short_hash(c.Id()),
					c.Type(),
					sw.hashname.Short(),
					l.peer.Hashname().Short())
				delete(l.channels, i)
			}
		}
	}

	sw.reactor.CastAfter(2*time.Second, cmd)
}

func stop_timer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

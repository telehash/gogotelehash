package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
	"time"
)

type peer_t struct {
	addr addr_t

	sw               *Switch
	prv_line_half    *private_line_key
	pub_line_half    *public_line_key
	line             *shared_line_key
	peer_cmd_snd_at  time.Time
	open_cmd_snd_at  time.Time
	last_dht_refresh time.Time
	snd_last_at      time.Time
	rcv_last_at      time.Time
	channels         map[string]*channel_t
	broken           bool

	mtx sync.RWMutex
	cnd sync.Cond
	log log.Logger
}

func make_peer(sw *Switch, hashname Hashname) *peer_t {
	peer := &peer_t{
		addr:        addr_t{hashname: hashname},
		sw:          sw,
		channels:    make(map[string]*channel_t, 100),
		log:         sw.peers.log.Sub(log_level_for("PEER", log.DEFAULT), hashname.Short()),
		snd_last_at: time.Now(),
		rcv_last_at: time.Now(),
	}

	peer.cnd.L = peer.mtx.RLocker()

	return peer
}

func (p *peer_t) String() string {
	return p.addr.String()
}

func (p *peer_t) open_channel(pkt *pkt_t, raw bool) (*channel_t, error) {
	channel, err := p.make_channel("", pkt.hdr.Type, true, raw)
	if err != nil {
		return nil, err
	}

	channel.log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.channel_id),
		pkt.hdr.Type,
		p.sw.peers.get_local_hashname().Short(),
		p.addr.hashname.Short())

	err = channel.snd_pkt(pkt)
	if err != nil {
		return nil, err
	}

	return channel, nil
}

func (p *peer_t) rcv_line_pkt(opkt *pkt_t) error {
	p.mtx.RLock()
	line := p.line
	p.mtx.RUnlock()

	if line == nil {
		return errUnknownLine
	}

	ipkt, err := line.dec(opkt)
	if err != nil {
		return err
	}

	err = p.push_rcv_pkt(ipkt)
	if err != nil {
		return err
	}

	p.mtx.Lock()
	p.rcv_last_at = time.Now()
	p.mtx.Unlock()

	return nil
}

func (p *peer_t) rcv_open_pkt(pub *public_line_key) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	var (
		err error
	)

	prv := p.prv_line_half
	if prv == nil {
		prv, err = make_line_half(p.sw.key, pub.rsa_pubkey)
		if err != nil {
			return err
		}
	}

	err = pub.verify(p.pub_line_half, p.sw.peers.get_local_hashname())
	if err != nil {
		return err
	}

	line, err := line_activate(prv, pub)
	if err != nil {
		return err
	}

	if p.prv_line_half == nil || p.pub_line_half != nil && p.pub_line_half.id != pub.id {
		pkt, err := prv.compose_open_pkt()
		if err != nil {
			return err
		}
		pkt.addr = p.addr

		err = p.sw.net.snd_pkt(pkt)
		if err != nil {
			return err
		}
	}

	p.prv_line_half = prv
	p.pub_line_half = pub
	p.line = line
	p.rcv_last_at = time.Now()

	p.log.Noticef("line opened: id=%s:%s",
		short_hash(prv.id),
		short_hash(pub.id))

	for _, c := range p.channels {
		c.cnd.Broadcast()
	}

	return nil
}

func (p *peer_t) push_rcv_pkt(pkt *pkt_t) error {
	pkt.addr = p.addr

	if pkt.hdr.C == "" {
		return errInvalidPkt
	}

	// send pkt to existing channel
	if channel := p.channels[pkt.hdr.C]; channel != nil {
		p.log.Debugf("rcv pkt: addr=%s hdr=%+v", p, pkt.hdr)
		return channel.push_rcv_pkt(pkt)
	}

	// open new channel
	if pkt.hdr.Type == "" {
		return errInvalidPkt
	}

	raw := !pkt.hdr.Seq.IsSet()

	if !raw && pkt.hdr.Seq.Get() != 0 {
		return errInvalidPkt
	}

	channel, err := p.make_channel(pkt.hdr.C, pkt.hdr.Type, false, raw)
	if err != nil {
		return err
	}

	p.log.Debugf("rcv pkt: addr=%s hdr=%+v", p, pkt.hdr)

	channel.log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.channel_id),
		pkt.hdr.Type,
		p.sw.peers.get_local_hashname().Short(),
		p.addr.hashname.Short())

	err = channel.push_rcv_pkt(pkt)
	if err != nil {
		return err
	}

	go channel.run_user_handler()

	return nil
}

func (p *peer_t) make_channel(id, typ string, initiator bool, raw bool) (*channel_t, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	channel, err := make_channel(p.sw, p, id, typ, initiator, raw)
	if err != nil {
		return nil, err
	}

	p.channels[channel.channel_id] = channel

	return channel, nil
}

func (p *peer_t) snd_pkt(pkt *pkt_t) error {
	p.log.Debugf("snd pkt: addr=%s hdr=%+v", p, pkt.hdr)

	p.mtx.RLock()
	var (
		broken = p.broken
		line   = p.line
		addr   = p.addr
	)
	p.mtx.RUnlock()

	if broken {
		return ErrPeerBroken
	}

	if line == nil {
		// drop
		return errNoOpenLine
	}

	pkt.addr = addr

	pkt, err := line.enc(pkt)
	if err != nil {
		return err
	}

	err = p.sw.net.snd_pkt(pkt)
	if err != nil {
		return err
	}

	p.mtx.Lock()
	p.snd_last_at = time.Now()
	p.mtx.Unlock()

	return nil
}

func (p *peer_t) snd_pkt_blocking(pkt *pkt_t) error {
	p.log.Debugf("snd pkt: addr=%s hdr=%+v", p, pkt.hdr)

	p.mtx.RLock()
	if p.line == nil {
		go p.open_line()
	}
	for p.line == nil && p.broken == false {
		p.cnd.Wait()
	}
	var (
		broken = p.broken
		line   = p.line
		addr   = p.addr
	)
	p.mtx.RUnlock()

	if broken {
		return ErrPeerBroken
	}

	pkt.addr = addr

	pkt, err := line.enc(pkt)
	if err != nil {
		return err
	}

	err = p.sw.net.snd_pkt(pkt)
	if err != nil {
		return err
	}

	p.mtx.Lock()
	p.snd_last_at = time.Now()
	p.mtx.Unlock()

	return nil
}

func (p *peer_t) has_open_line() bool {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.line != nil
}

func (p *peer_t) tick(now time.Time) {
	deadline := now.Add(-60 * time.Second)

	p.mtx.Lock()
	if !p.snd_last_at.Before(deadline) && p.rcv_last_at.Before(deadline) {
		p.broken = true
	}
	var (
		channels = make([]*channel_t, 0, len(p.channels))
		closed   []string
	)
	for _, c := range p.channels {
		channels = append(channels, c)
	}
	p.mtx.Unlock()

	for _, c := range channels {
		err := c.snd_ack()
		if err != nil {
			p.log.Debugf("auto-ack: error=%s", err)
		}

		c.send_missing_packets(now)
		c.detect_rcv_deadline(now)
		c.detect_broken(now)

		if p.broken {
			c.mark_as_broken()
		}

		if c.is_closed() {
			closed = append(closed, c.channel_id)

			if c.broken {
				c.log.Debugf("channel[%s:%s](%s -> %s): broken",
					short_hash(c.channel_id),
					c.channel_type,
					p.sw.peers.get_local_hashname().Short(),
					p.addr.hashname.Short())
			} else {
				c.log.Debugf("channel[%s:%s](%s -> %s): closed",
					short_hash(c.channel_id),
					c.channel_type,
					p.sw.peers.get_local_hashname().Short(),
					p.addr.hashname.Short())
			}
		}

	}

	if len(closed) > 0 {
		p.mtx.Lock()
		for _, id := range closed {
			delete(p.channels, id)
		}
		p.mtx.Unlock()
	}

	if p.last_dht_refresh.Before(now.Add(-30 * time.Second)) {
		p.last_dht_refresh = now
		go p.send_seek_cmd(p.sw.LocalHashname())
	}
}

func (p *peer_t) open_line() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.addr.pubkey == nil && !p.addr.via.IsZero() {
		p.peer_open_line()
	} else {
		p.self_open_line()
	}
}

func (peer *peer_t) self_open_line() error {
	peer.open_cmd_snd_at = time.Now()

	if peer.addr.hashname.IsZero() {
		peer.log.Debugf("line: open err=%s", "unreachable peer (missing hashname)")
		return errInvalidOpenReq
	}

	if peer.addr.addr == nil {
		peer.log.Debugf("line: open err=%s", "unreachable peer (missing address)")
		return errInvalidOpenReq
	}

	if peer.addr.pubkey == nil {
		return errMissingPublicKey
	}

	if peer.prv_line_half == nil {
		prv_line_half, err := make_line_half(peer.sw.key, peer.addr.pubkey)
		if err != nil {
			return err
		}
		peer.prv_line_half = prv_line_half
	}

	pkt, err := peer.prv_line_half.compose_open_pkt()
	pkt.addr = peer.addr

	err = peer.sw.net.snd_pkt(pkt)
	if err != nil {
		return err
	}

	return nil
}

func (p *peer_t) peer_open_line() {
	p.peer_cmd_snd_at = time.Now()

	p.send_peer_cmd()
}

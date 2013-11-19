package telehash

import (
	"github.com/fd/go-util/log"
	"sync"
	"time"
)

type peer_t struct {
	addr addr_t

	sw               *Switch
	line             line_t
	last_dht_refresh time.Time
	channels         map[string]*channel_t

	mtx sync.RWMutex
	cnd sync.Cond
	log log.Logger
}

func make_peer(sw *Switch, hashname Hashname) *peer_t {
	peer := &peer_t{
		addr:     addr_t{hashname: hashname},
		sw:       sw,
		channels: make(map[string]*channel_t, 100),
		log:      sw.peers.log.Sub(log_level_for("PEER", log.DEFAULT), hashname.Short()),
	}

	peer.line.Init(peer)

	peer.cnd.L = peer.mtx.RLocker()

	return peer
}

func (p *peer_t) IsGood() bool {
	return p.line.State().test(line_opened, 0)
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

/*

func (p *peer_t) has_open_line() bool {
  return p.line.State().test(line_opened, 0)
}
*/

func (p *peer_t) tick(now time.Time) {
	/*
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
	*/
}

/*
func (p *peer_t) open_line() {
  p.mtx.Lock()
  defer p.mtx.Unlock()

  if p.addr.pubkey == nil && !p.addr.via.IsZero() {
    p.peer_open_line()
  } else {
    p.self_open_line()
  }
}

func (p *peer_t) peer_open_line() {
  p.peer_cmd_snd_at = time.Now()

  p.send_peer_cmd()
}
*/

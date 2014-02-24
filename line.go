package telehash

import (
	"github.com/fd/go-util/log"
	"github.com/telehash/gogotelehash/runloop"
	"sync/atomic"
	"time"
)

const (
	line_broken_timeout = 120 * time.Second
)

type line_state uint32

const (
	line_pending line_state = iota
	line_peering
	line_opening
	line_pathing
	line_opened
	line_closed
)

var line_state_strings = map[line_state]string{
	line_pending: "pending",
	line_peering: "peering",
	line_opening: "opening",
	line_pathing: "pathing",
	line_opened:  "opened",
	line_closed:  "closed",
}

func (l line_state) String() string {
	return line_state_strings[l]
}

type line_t struct {
	sw   *Switch
	peer *Peer
	log  log.Logger

	prv_key *private_line_key
	pub_key *public_line_key
	shr_key *shared_line_key
	state   line_state

	backlog   runloop.Backlog
	channels  map[string]*Channel
	last_sync time.Time

	broken_timer *time.Timer
	open_timer   *time.Timer
}

func (l *line_t) Init(sw *Switch, peer *Peer) {
	l.sw = sw
	l.peer = peer
	l.log = sw.log.Sub(log_level_for("LINE", log.DEFAULT), "line["+l.peer.Hashname().Short()+"]")

	l.channels = make(map[string]*Channel, 10)

	l.broken_timer = sw.runloop.CastAfter(line_broken_timeout, &cmd_line_close_broken{l})
	l.open_timer = sw.runloop.CastAfter(line_broken_timeout, &cmd_line_close_down{l})
}

func (l *line_t) open_with_peer() {
	l.sw.send_nat_breaker(l.peer)
	l.sw.peer_handler.SendPeer(l.peer)
}

// atomically get the line state
func (l *line_t) State() line_state {
	if l == nil {
		return line_closed
	}
	return line_state(atomic.LoadUint32((*uint32)(&l.state)))
}

func (l *line_t) SndOpen(np *net_path) error {
	var (
		local_rsa_key = l.sw.Key
		netpaths      []*net_path
	)

	if np == nil {
		netpaths = l.peer.net_paths()
	} else {
		netpaths = []*net_path{np}
	}

	if l.peer.Hashname().IsZero() {
		l.log.Debugf("snd open to=%s err=%s", l.peer, errInvalidOpenReq)
		return errInvalidOpenReq
	}

	if len(netpaths) == 0 {
		l.log.Debugf("snd open to=%s err=%s", l.peer, errInvalidOpenReq)
		return ErrPeerBroken
	}

	if l.peer.PublicKey() == nil {
		l.log.Debugf("snd open to=%s err=%s", l.peer, errMissingPublicKey)
		return errMissingPublicKey
	}

	if l.prv_key == nil {
		prv_key, err := make_line_half(local_rsa_key, l.peer.PublicKey())
		if err != nil {
			l.log.Debugf("snd open to=%s err=%s", l.peer, err)
			return err
		}
		l.prv_key = prv_key
	}

	pkt, err := l.prv_key.compose_open_pkt()
	if err != nil {
		l.log.Debugf("snd open to=%s err=%s", l.peer, err)
		return err
	}
	pkt.peer = l.peer

	for _, np := range netpaths {
		pkt.netpath = np

		err = l.sw.snd_pkt(pkt)
		if err != nil {
			l.log.Debugf("snd open to=%s err=%s", l.peer, err)
		} else {
			l.log.Debugf("snd open to=%s", l.peer)
		}
	}

	return nil
}

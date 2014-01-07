package telehash

import (
	"github.com/fd/go-util/log"
	"sync/atomic"
	"time"
)

const (
	line_idle_timeout   = 55 * time.Second
	line_broken_timeout = 60 * time.Second
	line_path_interval  = 10 * time.Second
	line_seek_interval  = 30 * time.Second
)

type line_t struct {
	sw   *Switch
	peer *Peer
	log  log.Logger

	prv_key *private_line_key
	pub_key *public_line_key
	shr_key *shared_line_key
	state   line_state

	backlog  backlog_t
	channels map[string]*Channel

	idle_timer   *time.Timer
	broken_timer *time.Timer
	open_timer   *time.Timer
	path_timer   *time.Timer
	seek_timer   *time.Timer
}

func (l *line_t) Init(sw *Switch, peer *Peer) {
	l.sw = sw
	l.peer = peer
	l.log = sw.log.Sub(log_level_for("LINE", log.DEFAULT), "line["+l.peer.Hashname().Short()+"]")

	l.channels = make(map[string]*Channel, 10)

	l.idle_timer = sw.reactor.CastAfter(line_idle_timeout, &cmd_line_close_idle{l})
	l.broken_timer = sw.reactor.CastAfter(line_broken_timeout, &cmd_line_close_broken{l})
	l.open_timer = sw.reactor.CastAfter(line_broken_timeout, &cmd_line_close_down{l})
}

func (l *line_t) open_with_peer() {
	l.sw.net.send_nat_breaker(l.peer)
	l.sw.peer_handler.SendPeer(l.peer)
}

// atomically get the line state
func (l *line_t) State() line_state {
	if l == nil {
		return line_closed
	}
	return line_state(atomic.LoadUint32((*uint32)(&l.state)))
}

func (l *line_t) SndOpen(np NetPath) error {
	var (
		local_rsa_key = l.sw.key
		netpaths      []NetPath
	)

	if np == nil {
		netpaths = l.peer.NetPaths()
	} else {
		netpaths = []NetPath{np}
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
		np.Demote()
		pkt.netpath = np

		err = np.Send(l.sw, pkt)
		if err != nil {
			l.log.Debugf("snd open to=%s err=%s", l.peer, err)
		} else {
			l.log.Debugf("snd open to=%s", l.peer)
		}
	}

	return nil
}

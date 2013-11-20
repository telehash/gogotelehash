package telehash

import (
	"fmt"
	"sync/atomic"
	"time"
)

type line_state uint32

const (
	line_opened line_state = 1 << iota
	line_peering
	line_opening
	line_idle
	line_error
	line_broken
	line_running // is the goroutine running?

	line_active = line_opened | line_opening | line_peering
)

type line_t struct {
	sw            *Switch
	peer          *peer_t
	shutdown      chan bool
	snd_chan      chan line_snd_cmd
	rcv_open_chan chan *public_line_key // buffered rcv channel
	rcv_line_chan chan *pkt_t           // buffered rcv channel
	prv_key       *private_line_key
	pub_key       *public_line_key
	shr_key       *shared_line_key
	state         line_state
	err           error
}

type line_snd_cmd struct {
	pkt   *pkt_t
	reply chan error
}

func (l *line_t) Init(peer *peer_t) {
	l.sw = peer.sw
	l.peer = peer

	l.snd_chan = make(chan line_snd_cmd, 10)
	l.rcv_open_chan = make(chan *public_line_key, 10)
	l.rcv_line_chan = make(chan *pkt_t, 10)
}

// atomically get the line state
func (l *line_t) State() line_state {
	return line_state(atomic.LoadUint32((*uint32)(&l.state)))
}

func (l *line_t) LastErr() error {
	return l.err
}

// atomically start the line when necessary
func (l *line_t) EnsureRunning() error {
	for {
		old_state := l.State()

		if old_state.test(line_broken, 0) {
			return ErrPeerBroken
		}

		if old_state.test(line_running, 0) {
			return nil
		}

		new_state := old_state
		new_state.mod(line_running, 0)

		if atomic.CompareAndSwapUint32((*uint32)(&l.state), uint32(old_state), uint32(new_state)) {
			l.shutdown = make(chan bool, 1)
			go l.run_main_loop()
			return nil
		}
	}
}

func (l *line_t) Shutdown() {
	select {
	case l.shutdown <- true:
	default:
	}
}

func (l *line_t) Snd(pkt *pkt_t) error {
	err := l.EnsureRunning()
	if err != nil {
		return err
	}

	reply := make(chan error)
	l.snd_chan <- line_snd_cmd{pkt, reply}
	return <-reply
}

func (l *line_t) RcvLine(pkt *pkt_t) {
	if l.State().test(0, line_running) {
		return // drop
	}

	l.rcv_line_chan <- pkt
}

func (l *line_t) RcvOpen(pub *public_line_key) {
	err := l.EnsureRunning()
	if err != nil {
		return // drop
	}

	l.rcv_open_chan <- pub
}

func (l *line_t) run_main_loop() {
	defer l.teardown()

	if !l.handle_err(l.setup()) {
		return
	}

	for {
		switch {

		case l.state.test(line_opened, 0):
			l.run_line_loop()

		case l.state.test(0, line_active):
			return

		case l.state.test(line_peering, 0):
			l.run_peer_loop()

		case l.state.test(line_opening, 0):
			l.run_open_loop()

		}
	}
}

func (l *line_t) setup() error {
	l.peer.log.Debugf("started running line")

	l.register()

	if l.peer.addr.pubkey == nil && !l.peer.addr.via.IsZero() {
		l.state.mod(line_opening|line_peering, 0)
	} else {
		l.state.mod(line_opening, 0)
	}

	return nil
}

func (l *line_t) run_peer_loop() {
	if l.handle_err(l.peer.send_peer_cmd()) {
		l.state.mod(0, line_peering)
	} else {
		l.state.mod(0, line_active)
	}
}

// open procedure
func (l *line_t) run_open_loop() {
	var (
		timeout_d = 5 * time.Second
		timeout   = time.NewTimer(0)
		deadline  = time.NewTimer(60 * time.Second)
	)

	defer timeout.Stop()
	defer deadline.Stop()

	for l.state.test(line_opening, 0) {
		select {

		case <-l.shutdown:
			l.state.mod(0, line_active)

		case <-deadline.C:
			l.handle_err(fmt.Errorf("line opend failed: deadline reached"))
			l.state.mod(line_broken, line_active)

		case <-timeout.C:
			l.handle_err(l.snd_open_pkt())
			timeout.Reset(timeout_d)

		case pkt := <-l.rcv_open_chan:
			if l.handle_err(l.rcv_open_pkt(pkt)) {
				l.state.mod(line_opened, line_active)
			} else {
				l.state.mod(0, line_active)
			}

		}
	}
}

func (l *line_t) run_line_loop() {
	var (
		local_hashname = l.sw.peers.local_hashname
		broken_timeout = 60 * time.Second
		broken_timer   = time.NewTimer(broken_timeout)
		idle_timeout   = 30 * time.Second
		idle_timer     = time.NewTimer(idle_timeout)
		ack_ticker     = time.NewTicker(10 * time.Millisecond)
		seek_ticker    = time.NewTicker(30 * time.Second)
	)

	defer broken_timer.Stop()
	defer idle_timer.Stop()
	defer ack_ticker.Stop()
	defer seek_ticker.Stop()

	l.activate()
	defer l.deactivate()

	for l.state.test(line_opened, 0) {
		select {

		case <-l.shutdown:
			l.state.mod(0, line_active)

		case <-broken_timer.C:
			l.state.mod(line_broken, line_active)

		case <-idle_timer.C:
			l.state.mod(line_idle, line_active)

		case now := <-ack_ticker.C:
			for _, c := range l.peer.channels {
				ack, miss := c.tick(now)
				if ack != nil {
					l.snd_line_pkt(line_snd_cmd{ack, nil})
				}
				for _, pkt := range miss {
					l.snd_line_pkt(line_snd_cmd{pkt, nil})
				}
			}

		case <-seek_ticker.C:
			go l.peer.send_seek_cmd(local_hashname)

		case cmd := <-l.snd_chan:
			if l.handle_err(l.snd_line_pkt(cmd)) {
				idle_timer.Reset(idle_timeout)
			} else {
				l.state.mod(0, line_active) // connection is broken
			}

		case pkt := <-l.rcv_line_chan:
			if l.handle_err(l.rcv_line_pkt(pkt)) {
				idle_timer.Reset(idle_timeout)
				broken_timer.Reset(broken_timeout)
			}

		case <-l.rcv_open_chan:
			// ignore line reopens for now

		}
	}
}

func (l *line_t) rcv_line_pkt(opkt *pkt_t) error {
	ipkt, err := l.shr_key.dec(opkt)
	if err != nil {
		return err
	}

	err = l.peer.push_rcv_pkt(ipkt)
	if err != nil {
		return err
	}

	return nil
}

func (l *line_t) snd_line_pkt(cmd line_snd_cmd) error {
	pkt, err := l.shr_key.enc(cmd.pkt)
	if err != nil {
		if cmd.reply != nil {
			cmd.reply <- err
		}
		return err
	}

	pkt.addr = l.peer.addr

	err = l.sw.net.snd_pkt(pkt)
	if err != nil {
		if cmd.reply != nil {
			cmd.reply <- err
		}
		return err
	}

	if cmd.reply != nil {
		cmd.reply <- nil
	}
	return nil
}

func (l *line_t) rcv_open_pkt(pub *public_line_key) error {
	var (
		err            error
		local_rsa_key  = l.sw.key
		local_hashname = l.sw.peers.get_local_hashname()
	)

	prv := l.prv_key
	if prv == nil {
		prv, err = make_line_half(local_rsa_key, pub.rsa_pubkey)
		if err != nil {
			return err
		}
	}

	err = pub.verify(l.pub_key, local_hashname)
	if err != nil {
		return err
	}

	shr, err := line_activate(prv, pub)
	if err != nil {
		return err
	}

	if l.prv_key == nil || l.pub_key != nil && l.pub_key.id != pub.id {
		pkt, err := prv.compose_open_pkt()
		if err != nil {
			return err
		}
		pkt.addr = l.peer.addr

		err = l.sw.net.snd_pkt(pkt)
		if err != nil {
			return err
		}
	}

	l.prv_key = prv
	l.pub_key = pub
	l.shr_key = shr

	l.peer.log.Noticef("line opened: id=%s:%s",
		short_hash(prv.id),
		short_hash(pub.id))

	for _, c := range l.peer.channels {
		c.cnd.Broadcast()
	}

	return nil
}

func (l *line_t) snd_open_pkt() error {
	var (
		err           error
		local_rsa_key = l.sw.key
	)

	if l.peer.addr.hashname.IsZero() {
		return errInvalidOpenReq
	}

	if l.peer.addr.addr == nil {
		return errInvalidOpenReq
	}

	if l.peer.addr.pubkey == nil {
		return errMissingPublicKey
	}

	if l.prv_key == nil {
		prv_key, err := make_line_half(local_rsa_key, l.peer.addr.pubkey)
		if err != nil {
			return err
		}
		l.prv_key = prv_key
	}

	pkt, err := l.prv_key.compose_open_pkt()
	pkt.addr = l.peer.addr

	err = l.sw.net.snd_pkt(pkt)
	if err != nil {
		return err
	}

	return nil
}

func (l *line_t) teardown() {
	l.unregister()

	l.state.mod(0, line_active)

	l.break_channels()

	l.flush() // empty the buffers

	l.state.mod(0, line_running)
	l.peer.log.Debugf("stopped running line")
}

func (l *line_t) flush() {
	for {
		select {
		case <-l.rcv_open_chan:
		case <-l.rcv_line_chan:
		default:
			return
		}
	}
}

func (l *line_t) break_channels() {
	for _, c := range l.peer.channels {
		c.mark_as_broken()
	}

	// flush channel sends
	for {
		select {
		case cmd := <-l.snd_chan:
			cmd.reply <- ErrPeerBroken
		default:
			return
		}
	}
}

func (l *line_t) register() {
	l.sw.main.register_line_chan <- l
}

func (l *line_t) unregister() {
	l.sw.main.unregister_line_chan <- l
}

func (l *line_t) activate() {
	l.sw.main.activate_line_chan <- l
}

func (l *line_t) deactivate() {
	l.sw.main.deactivate_line_chan <- l
}

func (l *line_t) handle_err(err error) bool {
	if err != nil {
		l.err = err
		l.state.mod(line_error, 0)
		return false
	}
	return true
}

func (l line_state) test(is line_state, is_not line_state) bool {
	if is != 0 && l&is == 0 {
		return false
	}
	if is_not != 0 && l&is_not > 0 {
		return false
	}
	return true
}

func (lptr *line_state) mod(add, rem line_state) {
	l := *lptr
	l &^= rem
	l |= add
	*lptr = l
}

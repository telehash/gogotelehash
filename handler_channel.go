package telehash

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

type channel_t struct {
	conn *channel_handler

	id           string   // id of the channel
	peer         Hashname // hashname of the peer
	channel_type string   // type of the channel
	// snd_init_pkt bool
	// rcv_init_ack bool
	snd *channel_snd_buffer_t
	rcv *channel_rcv_buffer_t
	ack *channel_ack_handler_t
}

type channel_handler_iface interface {
	serve_telehash(channel *channel_t)
}

type channel_handler_func func(channel *channel_t)

func (f channel_handler_func) serve_telehash(channel *channel_t) {
	f(channel)
}

type channel_handler struct {
	conn         *line_handler
	peers        *peer_handler
	channels     map[string]*channel_t
	channels_mtx sync.Mutex
	handler      channel_handler_iface
}

type channel_handler_snd struct {
	pkt   *pkt_t
	reply chan error
}

func (h *channel_handler) _close_channels() {
	h.channels_mtx.Lock()
	defer h.channels_mtx.Unlock()

	for _, c := range h.channels {
		c.close_with_error("switch was terminated")
	}
}

func (h *channel_handler) reader_loop() {
	defer h._close_channels()

	for pkt := range h.conn.rcv {
		h.rcv_channel_pkt(pkt)
	}
}

func channel_handler_open(addr string, prvkey *rsa.PrivateKey, handler channel_handler_iface, peers *peer_handler) (*channel_handler, error) {
	conn, err := line_handler_open(addr, prvkey, peers)
	if err != nil {
		return nil, err
	}

	h := &channel_handler{
		conn:     conn,
		peers:    peers,
		channels: make(map[string]*channel_t),
		handler:  handler,
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go h.reader_loop()
	}

	return h, nil
}

func (h *channel_handler) close() {
	h.conn.close()
}

func (h *channel_handler) open_channel(hashname Hashname, pkt *pkt_t) (*channel_t, error) {
	id, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	channel := h.make_channel(hashname)
	channel.id = hex.EncodeToString(id)
	h.add_channel(channel)

	Log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.id),
		pkt.hdr.Type,
		channel.conn.peers.get_local_hashname().Short(),
		channel.peer.Short())

	err = channel.send(pkt)
	if err != nil {
		channel.close()
		return nil, err
	}

	return channel, nil
}

func (h *channel_handler) add_channel(c *channel_t) {
	h.channels_mtx.Lock()
	defer h.channels_mtx.Unlock()

	h.channels[c.id] = c
}

func (h *channel_handler) drop_channel(c *channel_t) {
	h.channels_mtx.Lock()
	defer h.channels_mtx.Unlock()

	delete(h.channels, c.id)
}

func (h *channel_handler) make_channel(peer Hashname) *channel_t {
	c := &channel_t{
		conn: h,
		peer: peer,
		rcv:  make_channel_rcv_buffer(),
		snd:  make_channel_snd_buffer(),
	}

	c.ack = make_channel_ack_handler(c.rcv, c.snd, c)

	return c
}

func (c *channel_t) SetReceiveDeadline(deadline time.Time) {
	c.rcv.set_deadline(deadline)
}

func (c *channel_t) close() error {
	return c.close_with_error("")
}

func (c *channel_t) close_with_error(err_message string) error {
	err := c.send(&pkt_t{hdr: pkt_hdr_t{End: true, Err: err_message}})

	c.ack.close()
	c.rcv.close()

	return err
}

func (c *channel_t) send(pkt *pkt_t) error {

	// mark the packet
	pkt.hdr.C = c.id

	// buffer the packet
	err := c.snd.put(pkt)
	if err != nil {
		return err
	}

	c.ack.add_ack_info(pkt)

	// send the packet
	err = c.conn.conn.send(c.peer, pkt)
	if err != nil {
		return err
	}

	return nil
}

func (c *channel_t) receive() (*pkt_t, error) {
	pkt, err := c.rcv.get()
	if err != nil {
		return nil, err
	}

	if pkt.hdr.Err != "" {
		err = errors.New(pkt.hdr.Err)
	}

	return pkt, err
}

func (h *channel_handler) rcv_channel_pkt(pkt *pkt_t) {

	if pkt.hdr.C == "" {
		return // drop; unknown channel
	}

	// Log.Debugf("channel[%s]: rcv %+v", pkt.hdr.C[:8], pkt)

	channel := h.channels[pkt.hdr.C]
	if channel == nil {
		if pkt.hdr.Type != "" {
			h.rcv_new_channel_pkt(pkt)
			return
		} else {
			return // drop; unknown channel
		}
	}

	if !pkt.JustAck() { // not just an ack
		channel.rcv.put(pkt)
		channel.ack.received_packet()
	}

	channel.ack.handle_ack_info(pkt)
}

func (h *channel_handler) rcv_new_channel_pkt(pkt *pkt_t) {
	peer_hashname, err := HashnameFromString(pkt.peer)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	channel := h.make_channel(peer_hashname)
	channel.id = pkt.hdr.C
	channel.channel_type = pkt.hdr.Type
	// channel.snd_init_pkt = true
	// channel.rcv_init_ack = true
	h.add_channel(channel)

	Log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.id),
		channel.channel_type,
		channel.conn.peers.get_local_hashname().Short(),
		channel.peer.Short())

	go channel.run_user_handler()

	channel.rcv.put(pkt)
	channel.ack.received_packet()
}

func (c *channel_t) run_user_handler() {
	defer func() {
		r := recover()
		if r != nil {
			Log.Errorf("panic: %s\n%s", r, debug.Stack())
			c.close_with_error("internal server error")
		} else {
			c.close()
		}
	}()

	c.conn.handler.serve_telehash(c)
}

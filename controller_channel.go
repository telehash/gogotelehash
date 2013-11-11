package telehash

import (
	"encoding/hex"
	"errors"
	"runtime/debug"
	"sync"
	"time"
)

type channel_t struct {
	sw *Switch

	id           string   // id of the channel
	peer         Hashname // hashname of the peer
	channel_type string   // type of the channel
	// snd_init_pkt bool
	// rcv_init_ack bool
	snd *channel_snd_buffer_t
	rcv *channel_rcv_buffer_t
	ack *channel_ack_handler_t
}

type channel_controller struct {
	sw       *Switch
	channels map[string]*channel_t
	mtx      sync.Mutex
}

func (h *channel_controller) close() {
	for _, c := range h.channels {
		c.close_with_error("switch was terminated")
	}
}

func channel_controller_open(sw *Switch) (*channel_controller, error) {

	h := &channel_controller{
		sw:       sw,
		channels: make(map[string]*channel_t),
	}

	return h, nil
}

func (h *channel_controller) open_channel(hashname Hashname, pkt *pkt_t) (*channel_t, error) {
	id, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	channel := h.make_channel(hashname)
	channel.id = hex.EncodeToString(id)
	channel.channel_type = pkt.hdr.Type
	h.add_channel(channel)

	err = channel.send(pkt)
	if err != nil {
		channel.close()
		return nil, err
	}

	Log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.id),
		pkt.hdr.Type,
		h.sw.peers.get_local_hashname().Short(),
		channel.peer.Short())

	return channel, nil
}

func (h *channel_controller) add_channel(c *channel_t) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	h.channels[c.id] = c
}

func (h *channel_controller) drop_channel(c *channel_t) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	delete(h.channels, c.id)
}

func (h *channel_controller) make_channel(peer Hashname) *channel_t {
	c := &channel_t{
		sw:   h.sw,
		peer: peer,
	}

	c.rcv = make_channel_rcv_buffer(c)
	c.snd = make_channel_snd_buffer(c)
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

	c.snd.close()
	c.rcv.close()
	c.ack.close()
	c.sw.channels.drop_channel(c)

	Log.Debugf("channel[%s:%s](%s -> %s): closed",
		short_hash(c.id),
		c.channel_type,
		c.sw.peers.get_local_hashname().Short(),
		c.peer.Short())

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
	err = c.sw.net.snd_pkt(c.peer, pkt)
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

func (h *channel_controller) rcv_pkt(pkt *pkt_t) error {

	if pkt.hdr.C == "" {
		return errInvalidPkt
	}

	// Log.Debugf("channel[%s]: rcv %+v", pkt.hdr.C[:8], pkt)

	channel := h.channels[pkt.hdr.C]
	if channel == nil {
		if pkt.hdr.Type != "" {
			h.rcv_new_channel_pkt(pkt)
			return nil
		} else {
			return errUnknownChannel
		}
	}

	if !pkt.JustAck() { // not just an ack
		channel.rcv.put(pkt)
		channel.ack.received_packet()
	}

	channel.ack.handle_ack_info(pkt)
	return nil
}

func (h *channel_controller) rcv_new_channel_pkt(pkt *pkt_t) {
	channel := h.make_channel(pkt.peer)
	channel.id = pkt.hdr.C
	channel.channel_type = pkt.hdr.Type
	// channel.snd_init_pkt = true
	// channel.rcv_init_ack = true
	h.add_channel(channel)

	Log.Debugf("channel[%s:%s](%s -> %s): opened",
		short_hash(channel.id),
		channel.channel_type,
		h.sw.peers.get_local_hashname().Short(),
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

	c.sw.mux.serve_telehash(c)
}

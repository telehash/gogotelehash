package telehash

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/fd/go-util/log"
	"github.com/gokyle/ecdh"
	"sync"
	"time"
)

type line_controller struct {
	sw            *Switch
	peering_lines map[Hashname]bool    // hashname -> bool
	opening_lines map[Hashname]*line_t // hashname -> line
	rcv_lines     map[string]*line_t   // line id  -> linex
	max_time_skew time.Duration
	mtx           sync.RWMutex
	cnd           *sync.Cond
	log           log.Logger
}

func line_controller_open(sw *Switch) (*line_controller, error) {

	h := &line_controller{
		sw:            sw,
		peering_lines: make(map[Hashname]bool),
		opening_lines: make(map[Hashname]*line_t),
		rcv_lines:     make(map[string]*line_t),
		max_time_skew: 15 * time.Minute,
		log:           sw.log.Sub(log_level_for("LINES", log.DEFAULT), "lines"),
	}

	h.cnd = sync.NewCond(h.mtx.RLocker())

	return h, nil
}

func (h *line_controller) rcv_pkt(outer_pkt *pkt_t) error {
	switch outer_pkt.hdr.Type {

	case "open":
		return h._rcv_open_pkt(outer_pkt)

	case "line":
		return h._rcv_line_pkt(outer_pkt)

	default:
		// h.log.Debugf("rcv pkt err=%s pkt=%#v", errInvalidPkt, outer_pkt)
		return errInvalidPkt

	}
}

func (h *line_controller) _rcv_line_pkt(opkt *pkt_t) error {
	line := h._get_rcv_line(opkt.hdr.Line)
	if line == nil {
		return errUnknownLine
	}

	return line.rcv_pkt(opkt)
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-processing-1
func (h *line_controller) _rcv_open_pkt(opkt *pkt_t) error {
	pub_line_half, err := decompose_open_pkt(h.sw.key, opkt)
	if err != nil {
		return err
	}

	discovered := false
	peer := h.sw.peers.get_peer(public_line_half.hashname)
	if peer == nil {
		addr := opkt.addr.update(addr_t{hashname: public_line_half.hashname, pubkey: pub_line_half.rsa_pubkey})
		peer, discovered = h.sw.peers.add_peer(addr)
	}

	err = public_line_half.verify(peer.pub_line_half, peer.prv_line_half)
	if err != nil {
		return err
	}

	return nil
}

func (h *line_controller) _drop_line(line *line_t, err error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	delete(h.peering_lines, line.peer.addr.hashname)
	delete(h.opening_lines, line.peer.addr.hashname)
	delete(h.rcv_lines, line.rcv_id)
	line.peer.deactivate_line(line)
	h.cnd.Broadcast()
}

func (h *line_controller) _get_rcv_line(id string) *line_t {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.rcv_lines[id]
}

func (h *line_controller) tick(now time.Time) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// if there was no activity on a line in the last 15 seconds
	deadline := now.Add(-60 * time.Second)

	for _, line := range h.rcv_lines {

		if line.get_last_activity().Before(deadline) {

			line.peer.deactivate_line(line)
			delete(h.rcv_lines, line.rcv_id)

			h.log.Infof("line closed: %s:%s (%s -> %s)",
				short_hash(line.rcv_id),
				short_hash(line.snd_id),
				h.sw.peers.get_local_hashname().Short(),
				line.peer.addr.hashname.Short())

			continue
		}

		if line.get_last_rcv().Before(deadline) {

			line.peer.deactivate_line(line)
			delete(h.rcv_lines, line.rcv_id)

			line.peer.mark_as_broken()

			h.log.Infof("line broken: %s:%s (%s -> %s)",
				short_hash(line.rcv_id),
				short_hash(line.snd_id),
				h.sw.peers.get_local_hashname().Short(),
				line.peer.addr.hashname.Short())

			continue
		}
	}
}

package telehash

import (
	"encoding/hex"
	"github.com/fd/go-util/log"
	"github.com/gokyle/ecdh"
	"sync"
	"time"
)

type line_t struct {
	sw            *Switch
	peer          *peer_t
	ecc_prvkey    *ecdh.PrivateKey // (non-nil during open phase)
	ecc_pubkey    *ecdh.PublicKey  // (non-nil during open phase)
	snd_id        string           // line id used when sending packets
	rcv_id        string           // line id used when receiving packets
	snd_at        time.Time        // when the line was opened on the local side
	rcv_at        time.Time        // when the line was opened on the remote side
	enc_key       []byte           // aes key used when sending packets
	dec_key       []byte           // aes key  used when receiving packets
	last_activity time.Time
	last_rcv      time.Time
	rcv_buf       []*pkt_t
	mtx           sync.RWMutex
	log           log.Logger
}

func make_line(sw *Switch, peer *peer_t, line_id string) *line_t {
	return &line_t{
		sw:     sw,
		peer:   peer,
		rcv_id: line_id,
		log:    sw.lines.log.Sub(log.DEFAULT, short_hash(line_id)),
	}
}

// Send a packet over a line.
// This function will wrap the packet in a line packet.
func (line *line_t) snd_pkt(ipkt *pkt_t) error {
	line.log.Debugf("snd pkt: line=%s:%s addr=%s hdr=%+v",
		short_hash(line.snd_id),
		short_hash(line.rcv_id),
		line.peer, ipkt.hdr)

	ipkt_data, err := ipkt.format_pkt()
	if err != nil {
		return err
	}

	iv, err := make_rand(16)
	if err != nil {
		return err
	}

	ipkt_data, err = enc_AES_256_CTR(line.enc_key, iv, ipkt_data)
	if err != nil {
		return err
	}

	opkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "line",
			Line: line.snd_id,
			Iv:   hex.EncodeToString(iv),
		},
		body: ipkt_data,
		addr: line.peer.addr,
	}

	line.touch(false)

	return line.sw.net.snd_pkt(opkt)
}

func (line *line_t) rcv_pkt(opkt *pkt_t) error {
	var (
		ipkt *pkt_t
		iv   []byte
		err  error
	)

	if opkt.hdr.Type != "line" {
		return errInvalidPkt
	}

	// line is not fully opend yet
	if len(line.dec_key) == 0 {
		line.mtx.Lock()
		line.rcv_buf = append(line.rcv_buf, opkt)
		line.mtx.Unlock()
		return nil
	}

	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		return errInvalidPkt
	}

	opkt.body, err = dec_AES_256_CTR(line.dec_key, iv, opkt.body)
	if err != nil {
		return errInvalidPkt
	}

	ipkt, err = parse_pkt(opkt.body, line.peer.addr)
	if err != nil {
		return errInvalidPkt
	}

	line.touch(true)

	line.log.Debugf("rcv pkt: line=%s:%s addr=%s hdr=%+v",
		short_hash(line.snd_id),
		short_hash(line.rcv_id),
		line.peer, ipkt.hdr)

	return line.peer.push_rcv_pkt(ipkt)
}

func (l *line_t) touch(is_rcv bool) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	now := time.Now()
	l.last_activity = now
	if is_rcv {
		l.last_rcv = now
	}
}

func (l *line_t) get_last_activity() time.Time {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	return l.last_activity
}

func (l *line_t) get_last_rcv() time.Time {
	l.mtx.RLock()
	defer l.mtx.RUnlock()

	return l.last_rcv
}

package telehash

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

type pkt_line struct {
	Type   string          `json:"type,omitempty"`
	Line   string          `json:"line,omitempty"`
	Iv     string          `json:"iv,omitempty"`
	C      string          `json:"c,omitempty"`
	End    bool            `json:"end,omitempty"`
	Err    string          `json:"err,omitempty"`
	Custom json.RawMessage `json:"_,omitempty"`
}

func (l *line_t) send_pkt(ipkt *pkt_t) error {
	ipkt_data, err := ipkt.format_pkt()
	if err != nil {
		return err
	}

	iv, err := make_rand(16)
	if err != nil {
		return err
	}

	ipkt_data, err = enc_AES_256_CTR(l.enc_key, iv, ipkt_data)
	if err != nil {
		return err
	}

	opkt := pkt_t{
		hdr: pkt_hdr_t{
			Type: "line",
			Line: hex.EncodeToString(l.LineIn),
			Iv:   hex.EncodeToString(iv),
		},
		body: ipkt_data,
	}

	pkt, err := opkt.format_pkt()
	if err != nil {
		return err
	}

	l._switch.o_queue <- pkt_udp_t{l.peer.addr, pkt}
	return nil
}

func (l *line_t) handle_pkt(opkt *pkt_t) {
	var (
		ipkt *pkt_t
		iv   []byte
		err  error
	)

	if opkt.hdr.Type != "line" {
		Log.Debugf("dropped packet: %+v (error: %s)", opkt, "unexpected pkt type")
		return
	}

	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	opkt.body, err = dec_AES_256_CTR(l.dec_key, iv, opkt.body)
	if err != nil {
		Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	ipkt, err = parse_pkt(opkt.body, opkt.addr)
	if err != nil {
		Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	switch ipkt.hdr.Type {

	case "": // lookup existing channel
		channel := l._switch.channels[ipkt.hdr.C]
		if channel == nil {
			// drop pkt; unknown channel
			Log.Debugf("dropped packet: unknown channel %q", ipkt.hdr.C)
			return
		}
		channel.i_queue <- ipkt

	case "seek": // make a Seek channel
		channel := make_channel(l.peer)
		channel.id = ipkt.hdr.C
		channel.snd_init_pkt = true
		channel.rcv_init_ack = true
		l._switch.channels[channel.id] = channel
		channel.i_queue <- ipkt
		// pass to seek command
		// auto accept channel

	case "peer": // make a Peer channel
		channel := make_channel(l.peer)
		channel.id = ipkt.hdr.C
		channel.snd_init_pkt = true
		channel.rcv_init_ack = true
		l._switch.channels[channel.id] = channel
		channel.i_queue <- ipkt
		// pass to peer command
		// auto accept channel

	case "connect": // make a Connect channel
		channel := make_channel(l.peer)
		channel.id = ipkt.hdr.C
		channel.snd_init_pkt = true
		channel.rcv_init_ack = true
		l._switch.channels[channel.id] = channel
		channel.i_queue <- ipkt
		// pass to connect command
		// auto accept channel

	default:
		if strings.HasPrefix(ipkt.hdr.Type, "_") {
			// make a custom channel
			channel := make_channel(l.peer)
			channel.id = ipkt.hdr.C
			channel.snd_init_pkt = true
			channel.rcv_init_ack = true
			if l._switch.channels[channel.id] != nil {
				// drop pkt; channel already exists
				Log.Debugf("dropped packet: channel already exists %q", ipkt.hdr.C)
				return
			}
			l._switch.channels[channel.id] = channel
			channel.i_queue <- ipkt
			l._switch.a_queue <- channel

		} else {
			Log.Debugf("dropped packet: %+q (error: %s)", opkt, "invalid channel type")
			return
		}
	}

}

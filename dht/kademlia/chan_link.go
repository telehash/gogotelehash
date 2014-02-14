package kademlia

import (
	"time"

	"github.com/telehash/gogotelehash"
)

type link_t struct {
	dht          *DHT
	seed         bool // peer is a seed
	log_distance int
	peer         *telehash.Peer
	channel      *telehash.Channel
}

type link_header struct {
	Seed bool     `json:"seek"`
	See  []string `json:"see,omitempty"`
}

func (d *DHT) open_link(peer *telehash.Peer) error {
	channel, err := peer.Open(telehash.ChannelOptions{Type: "link", Reliablility: telehash.UnreliableChannel})
	if err != nil {
		return err
	}

	l := &link_t{
		dht:     d,
		channel: channel,
	}

	go l.run_requester()
	return nil
}

func (d *DHT) serve_link(channel *telehash.Channel) {
	l := &link_t{
		dht:     d,
		channel: channel,
	}

	l.run_responder()
}

func (l *link_t) run_requester() {
	l.setup()
	defer l.cleanup()

	for {
		var (
			hdr_in  link_header
			hdr_out link_header
			err     error
		)

		// announce seeder ability
		hdr_out.Seed = !l.dht.DisableSeed

		_, err = l.channel.SendPacket(&hdr_out, nil)
		if err != nil {
			return
		}

		l.channel.SetReceiveDeadline(time.Now().Add(5 * time.Second))

		_, err = l.channel.ReceivePacket(&hdr_in, nil)
		if err != nil {
			return
		}

		l.handle_pkt(&hdr_in)
	}
}

func (l *link_t) run_responder() {
	l.setup()
	defer l.cleanup()

	for {
		var (
			hdr_in  link_header
			hdr_out link_header
			err     error
		)

		l.channel.SetReceiveDeadline(time.Now().Add(120 * time.Second))

		_, err = l.channel.ReceivePacket(&hdr_in, nil)
		if err != nil {
			return
		}

		l.handle_pkt(&hdr_in)

		// announce seeder ability
		hdr_out.Seed = !l.dht.DisableSeed

		_, err = l.channel.SendPacket(&hdr_out, nil)
		if err != nil {
			return
		}
	}
}

func (l *link_t) handle_pkt(hdr_in *link_header) {

	// when seed changed
	if l.seed != hdr_in.Seed {
		l.seed = hdr_in.Seed

		if l.seed {
			// add to seek table
			l.dht.runloop.Cast(&cmd_seek_table_add{l})
		} else {
			// remove from seek table
			l.dht.runloop.Cast(&cmd_seek_table_remove{l})
		}
	}
}

func (l *link_t) setup() {
	l.peer = l.channel.Peer()
	l.log_distance = kad_bucket_for(l.dht.table.local_hashname, l.peer.Hashname())

	l.dht.runloop.Cast(&cmd_link_add{l})
}

func (l *link_t) cleanup() {
	l.channel.Close()

	if l.seed {
		l.dht.runloop.Cast(&cmd_seek_table_remove{l})
	}

	l.dht.runloop.Cast(&cmd_link_remove{l})
}

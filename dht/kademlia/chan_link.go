package kademlia

import (
	"github.com/telehash/gogotelehash"
	"time"
)

type link_t struct {
	dht          *DHT
	seed         bool // peer is a seed
	log_distance int
	peer         *telehash.Peer
	channel      *telehash.Channel
	created_at   time.Time
	last_seen    time.Time
}

type link_header struct {
	Seed bool     `json:"seed"`
	See  []string `json:"see,omitempty"`
}

func (d *DHT) open_link(peer *telehash.Peer) error {
	cmd := cmd_link_open{peer: peer}
	err := d.runloop.Call(&cmd)
	if err != nil {
		return err
	}
	return nil
}

func (d *DHT) serve_link(channel *telehash.Channel) {
	cmd := cmd_link_open{peer: channel.Peer(), channel: channel}
	err := d.runloop.Call(&cmd)
	if err != nil {
		telehash.Log.Errorf("dht: error=%s", err)
		return
	}

	cmd.link.run_responder()
}

func (l *link_t) run_requester() {
	defer l.cleanup()

	channel, err := l.peer.Open(telehash.ChannelOptions{Type: "link", Reliablility: telehash.UnreliableChannel})
	if err != nil {
		return
	}
	l.channel = channel

	telehash.Log.Errorf("opened link: link=%p peer=%s type=requester", l, l.peer.Hashname().Short())

	for {
		var (
			hdr_in  link_header
			hdr_out link_header
			now     = time.Now()
			err     error
		)

		// announce seeder ability
		hdr_out.Seed = !l.dht.DisableSeed

		// help fill buckets of peer
		closest := l.dht.closest_links(l.peer.Hashname(), 9)
		hdr_out.See = l.dht.encode_see_entries(closest)

		_, err = l.channel.SendPacket(&hdr_out, nil)
		if err != nil {
			return
		}

		l.channel.SetReceiveDeadline(time.Now().Add(50 * time.Second))

		_, err = l.channel.ReceivePacket(&hdr_in, nil)
		if err != nil {
			return
		}

		l.handle_pkt(&hdr_in)

		time.Sleep(now.Sub(time.Now()) + 55*time.Second)
	}
}

func (l *link_t) run_responder() {
	var (
		last_snd time.Time
	)

	telehash.Log.Errorf("opened link: link=%p peer=%s type=responder", l, l.peer.Hashname().Short())

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

		if last_snd.Before(time.Now().Add(-10 * time.Second)) {
			// announce seeder ability
			hdr_out.Seed = !l.dht.DisableSeed

			// help fill buckets of peer
			closest := l.dht.closest_links(l.peer.Hashname(), 9)
			hdr_out.See = l.dht.encode_see_entries(closest)

			_, err = l.channel.SendPacket(&hdr_out, nil)
			if err != nil {
				return
			}

			last_snd = time.Now()
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

	// open links to .See
	if len(hdr_in.See) > 0 {
		peers := l.dht.decode_see_entries(hdr_in.See, l.peer)
		for _, peer := range peers {
			go l.dht.open_link(peer)
		}
	}

	l.last_seen = time.Now()
}

func (l *link_t) setup() {
	l.created_at = time.Now()
	l.last_seen = l.created_at
	l.log_distance = kad_bucket_for(l.dht.table.local_hashname, l.peer.Hashname())
}

func (l *link_t) cleanup() {
	if l.channel != nil {
		l.channel.Close()
	}

	if l.seed {
		l.dht.runloop.Cast(&cmd_seek_table_remove{l})
	}

	l.dht.runloop.Cast(&cmd_link_remove{l})
}

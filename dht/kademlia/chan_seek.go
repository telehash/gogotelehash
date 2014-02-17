package kademlia

import (
	"github.com/telehash/gogotelehash"
	"time"
)

type seek_header struct {
	Seek string   `json:"seek,omitempty"`
	See  []string `json:"see,omitempty"`
	end  bool
}

func (hdr *seek_header) End() bool { return hdr.end }

func (d *DHT) cmd_seek(seek telehash.Hashname, via *telehash.Peer) ([]*telehash.Peer, error) {
	var (
		options    telehash.ChannelOptions
		req_header seek_header
		res_header seek_header
	)

	req_header = seek_header{
		Seek: seek.String(),
	}

	options = telehash.ChannelOptions{
		Type:         "seek",
		Reliablility: telehash.UnreliableChannel,
	}

	telehash.Log.Errorf("seek(client): snd %+v", req_header)

	channel, err := via.Open(options)
	if err != nil {
		return nil, err
	}
	defer channel.Close()

	channel.SetReceiveDeadline(time.Now().Add(5 * time.Second))

	_, err = channel.SendPacket(&req_header, nil)
	if err != nil {
		return nil, err
	}

	_, err = channel.ReceivePacket(&res_header, nil)
	if err != nil {
		return nil, err
	}

	telehash.Log.Errorf("seek(client): rcv %+v", res_header)
	peers := d.decode_see_entries(res_header.See, via)
	return peers, nil
}

func (d *DHT) do_seek(target telehash.Hashname, in <-chan *telehash.Peer, out chan<- *telehash.Peer) {
	defer func() { recover() }()

	for via := range in {
		peers, _ := d.cmd_seek(target, via)
		for _, peer := range peers {
			out <- peer
		}
		out <- nil
	}
}

func (d *DHT) serve_seek(channel *telehash.Channel) {
	var (
		req_header seek_header
		res_header seek_header
		closest    []*link_t
	)

	_, err := channel.ReceivePacket(&req_header, nil)
	if err != nil {
		return // drop
	}

	telehash.Log.Errorf("seek(server): rcv %+v", req_header)

	seek, err := telehash.HashnameFromString(req_header.Seek)
	if err != nil {
		return // drop
	}

	if link := d.get_link(seek); link != nil {
		closest = []*link_t{link}
	} else {
		closest = d.closest_links(seek, 25)
	}

	res_header.See = d.encode_see_entries(closest)
	res_header.end = true

	_, err = channel.SendPacket(&res_header, nil)
	if err != nil {
		return
	}

	telehash.Log.Errorf("seek(server): snd %+v", res_header)
}

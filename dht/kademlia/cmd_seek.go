package kademlia

import (
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
	"strings"
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

	peers := make([]*telehash.Peer, 0, len(res_header.See))

	for _, rec := range res_header.See {
		fields := strings.Split(rec, ",")

		hashname, err := telehash.HashnameFromString(fields[0])
		if err != nil {
			continue
		}

		if hashname == d.sw.LocalHashname() {
			// add address to main
			// detect nat
			continue // is self
		}

		if hashname == via.Hashname() {
			continue
		}

		peer := d.sw.GetPeer(hashname, true)
		peer.AddVia(via.Hashname())

		peers = append(peers, peer)

		if len(fields) > 1 {
			net, addr, err := net.DecodeSee(fields[1:])
			if err == nil && net != "" {
				peer.AddAddress(net, addr)
			}
		}
	}

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
	)

	_, err := channel.ReceivePacket(&req_header, nil)
	if err != nil {
		return // drop
	}

	seek, err := telehash.HashnameFromString(req_header.Seek)
	if err != nil {
		return // drop
	}

	closest := d.table.find_closest_peers(seek, 25)
	see := make([]string, 0, len(closest))

	for _, peer := range closest {
		if peer.PublicKey() == nil {
			continue // unable to forward peer requests to unless we know the public key
		}

		if !peer.IsConnected() {
			continue
		}

		fields := peer.FormatSeeAddress()
		if len(fields) > 0 {
			see = append(see, peer.Hashname().String()+","+strings.Join(fields, ","))
		} else {
			see = append(see, peer.Hashname().String())
		}
	}

	res_header.See = see
	res_header.end = true

	_, err = channel.SendPacket(&res_header, nil)
	if err != nil {
		return
	}
}

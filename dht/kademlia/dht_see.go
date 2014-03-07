package kademlia

import (
	"errors"
	"github.com/telehash/gogotelehash"
	"github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/iputil"
	"github.com/telehash/gogotelehash/net/ipv4"
	rnet "net"
	"strconv"
	"strings"
)

func (d *DHT) encode_see_entries(links []*link_t) []string {
	see := make([]string, 0, len(links))

	for _, link := range links {
		entry, err := encode_see_entry(link)
		if err != nil {
			continue
		}

		see = append(see, entry)
	}

	return see
}

func encode_see_entry(link *link_t) (string, error) {
	var (
		peer   = link.peer
		fields []string
	)

	if peer.PublicKey() == nil {
		return "", errors.New("missing public key")
	}

	fields = append(fields, peer.Hashname().String())

	if net, addr := peer.ActivePath(); net == "ipv4" && addr != nil {
		if a, ok := addr.(*ipv4.Addr); ok && a != nil && a.Category == iputil.CategoryWAN {
			fields = append(fields, a.IP.String(), strconv.Itoa(a.Port))
		}
	}

	return strings.Join(fields, ","), nil
}

func (d *DHT) decode_see_entries(entries []string, via *telehash.Peer) []*telehash.Peer {
	var (
		peers = make([]*telehash.Peer, 0, len(entries))
	)

	for _, entry := range entries {
		hashname, net, addr, err := decode_see_entry(entry)
		if err != nil {
			continue
		}

		if hashname == d.sw.LocalHashname() {
			continue // is self
		}

		if via != nil && hashname == via.Hashname() {
			continue
		}

		peer := d.sw.GetPeer(hashname, true)
		if via != nil {
			peer.AddVia(via.Hashname())
		}
		if net != "" && addr != nil {
			peer.AddAddress(net, addr)
		}

		peers = append(peers, peer)
	}

	return peers
}

func decode_see_entry(entry string) (telehash.Hashname, string, net.Addr, error) {
	var (
		hashname telehash.Hashname
		addr     net.Addr
		net      string
		fields   []string
		err      error
	)

	fields = strings.Split(entry, ",")

	hashname, err = telehash.HashnameFromString(fields[0])
	if err != nil {
		return telehash.ZeroHashname, "", nil, err
	}

	if len(fields) > 1 {
		addr, err = decode_ipv4_see_entry(fields[1:])
		if err != nil {
			return telehash.ZeroHashname, "", nil, err
		}
		net = "ipv4"
	}

	return hashname, net, addr, nil
}

func decode_ipv4_see_entry(fields []string) (net.Addr, error) {
	if len(fields) != 2 {
		return nil, errors.New("invalid ipv4 see entry")
	}

	addr, err := ipv4.ResolveAddr(rnet.JoinHostPort(fields[0], fields[1]))
	if err != nil {
		return nil, errors.New("invalid ipv4 see entry")
	}

	return addr, nil
}

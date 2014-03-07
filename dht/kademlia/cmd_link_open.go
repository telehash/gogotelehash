package kademlia

import (
	"errors"
	"github.com/telehash/gogotelehash"
)

type cmd_link_open struct {
	peer    *telehash.Peer
	channel *telehash.Channel
	link    *link_t
}

func (cmd *cmd_link_open) Exec(state interface{}) error {
	var (
		dht          = state.(*DHT)
		peer         = cmd.peer
		channel      = cmd.channel
		hashname     telehash.Hashname
		is_requester bool
	)

	if channel == nil {
		// do we already have an opened link?
		if link, found := dht.links[peer.Hashname()]; found {
			cmd.link = link
			return nil
		}

		// otherwise open a new link
		is_requester = true
		telehash.Log.Errorf("opening link: to=%s", peer.Hashname().Short())
	}

	hashname = peer.Hashname()

	link := &link_t{
		dht:     dht,
		channel: channel,
		peer:    peer,
	}

	link.setup()

	if _, found := dht.links[hashname]; found {
		cmd.link = link
		return errors.New("link already opened")
	}

	dht.links[hashname] = link

	if is_requester {
		go link.run_requester()
	}

	cmd.link = link
	return nil
}

package kademlia

type cmd_link_remove struct {
	link *link_t
}

func (cmd *cmd_link_remove) Exec(state interface{}) error {
	var (
		dht      = state.(*DHT)
		hashname = cmd.link.peer.Hashname()
	)

	// link was claimed by another channel
	if other, found := dht.links[hashname]; found && other != cmd.link {
		return nil
	}

	delete(dht.links, hashname)
	return nil
}

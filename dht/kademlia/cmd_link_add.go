package kademlia

type cmd_link_add struct {
	link *link_t
}

func (cmd *cmd_link_add) Exec(state interface{}) error {
	var (
		dht      = state.(*DHT)
		hashname = cmd.link.channel.To()
	)

	dht.links[hashname] = cmd.link
	return nil
}

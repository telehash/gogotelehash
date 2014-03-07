package kademlia

type cmd_seek_table_add struct {
	link *link_t
}

func (cmd *cmd_seek_table_add) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	dht.table.add(cmd.link)
	return nil
}

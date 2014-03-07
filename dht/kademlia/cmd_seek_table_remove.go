package kademlia

type cmd_seek_table_remove struct {
	link *link_t
}

func (cmd *cmd_seek_table_remove) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	dht.table.remove(cmd.link)
	return nil
}

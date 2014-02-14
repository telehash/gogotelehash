package kademlia

type cmd_shutdown struct{}

func (cmd *cmd_shutdown) Exec(state interface{}) error {
	var (
		dht = state.(*DHT)
	)

	// close all links

	dht.running = false
	return nil
}

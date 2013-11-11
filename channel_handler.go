package telehash

type channel_controller_iface interface {
	serve_telehash(channel *channel_t)
}

type channel_controller_func func(channel *channel_t)

func (f channel_controller_func) serve_telehash(channel *channel_t) {
	f(channel)
}

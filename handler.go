package telehash

type Handler interface {
	ServeTelehash(ch channel_i)
}

type HandlerFunc func(channel_i)

func (f HandlerFunc) ServeTelehash(ch channel_i) {
	f(ch)
}

package telehash

type Handler interface {
	ServeTelehash(ch *Channel)
}

type HandlerFunc func(*Channel)

func (f HandlerFunc) ServeTelehash(ch *Channel) {
	f(ch)
}

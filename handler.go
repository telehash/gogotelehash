package telehash

type Handler interface {
	ServeTelehash(ch *Channel)
}

type HandlerFunc func(*Channel)

func (f HandlerFunc) ServeTelehash(ch *Channel) {
	f(ch)
}

type wrappingHandler struct {
	h Handler
}

func (h wrappingHandler) serve_telehash(c *channel_t) {
	h.h.ServeTelehash(&Channel{c})
}

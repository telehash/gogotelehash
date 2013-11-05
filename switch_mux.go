package telehash

type SwitchMux struct {
	channel_types map[string]channel_handler_iface
	fallback      channel_handler_iface
}

func NewSwitchMux() *SwitchMux {
	return &SwitchMux{
		channel_types: make(map[string]channel_handler_iface),
	}
}

func (s *SwitchMux) ServeTelehash(c *Channel) {
	s.serve_telehash(c.c)
}

func (s *SwitchMux) serve_telehash(c *channel_t) {
	h := s.channel_types[c.channel_type]
	if h == nil {
		h = s.fallback
	}
	if h != nil {
		h.serve_telehash(c)
	}
}

func (s *SwitchMux) handle_fallback(h channel_handler_iface) {
	s.fallback = h
}

func (s *SwitchMux) handle_fallback_func(f func(*channel_t)) {
	s.handle_fallback(channel_handler_func(f))
}

func (s *SwitchMux) handle(typ string, h channel_handler_iface) {
	s.channel_types[typ] = h
}

func (s *SwitchMux) handle_func(typ string, f func(*channel_t)) {
	s.handle(typ, channel_handler_func(f))
}

func (s *SwitchMux) HandleFallback(h Handler) {
	s.fallback = wrappingHandler{h}
}

func (s *SwitchMux) HandleFallbackFunc(f func(*Channel)) {
	s.HandleFallback(HandlerFunc(f))
}

func (s *SwitchMux) Handle(typ string, h Handler) {
	s.handle(typ, wrappingHandler{h})
}

func (s *SwitchMux) HandleFunc(typ string, f func(*Channel)) {
	s.Handle(typ, HandlerFunc(f))
}

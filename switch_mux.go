package telehash

type SwitchMux struct {
	channel_types map[string]Handler
	fallback      Handler
}

func NewSwitchMux() *SwitchMux {
	return &SwitchMux{
		channel_types: make(map[string]Handler),
	}
}

func (s *SwitchMux) ServeTelehash(c Channel) {
	h := s.channel_types[c.Type()]
	if h == nil {
		h = s.fallback
	}
	if h != nil {
		h.ServeTelehash(c)
	}
}

func (s *SwitchMux) HandleFallback(h Handler) {
	s.fallback = h
}

func (s *SwitchMux) HandleFallbackFunc(f func(Channel)) {
	s.HandleFallback(HandlerFunc(f))
}

func (s *SwitchMux) Handle(typ string, h Handler) {
	s.channel_types[typ] = h
}

func (s *SwitchMux) HandleFunc(typ string, f func(Channel)) {
	s.Handle(typ, HandlerFunc(f))
}

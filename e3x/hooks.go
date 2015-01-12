package e3x

import (
	"errors"
	"net"
)

var ErrStopPropagation = errors.New("observer: stop propagation")

type EndpointHooks struct {
	endpoint *Endpoint
	hooks    []EndpointHook
}
type ExchangeHooks struct {
	endpoint *Endpoint
	exchange *Exchange
	hooks    []ExchangeHook
}
type ChannelHooks struct {
	endpoint *Endpoint
	exchange *Exchange
	channel  *Channel
	hooks    []ChannelHook
}

type EndpointHook struct {
	OnNetChanged func(e *Endpoint, up, down []net.Addr) error
	OnDropPacket func(e *Endpoint, msg []byte, conn net.Conn, reason error) error
}

type ExchangeHook struct {
	OnSessionReset func(*Endpoint, *Exchange) error
	OnOpened       func(*Endpoint, *Exchange) error
	OnClosed       func(*Endpoint, *Exchange, error) error
	OnDropPacket   func(e *Endpoint, x *Exchange, msg []byte, pipe *Pipe, reason error) error
}

type ChannelHook struct {
	OnOpened func(*Endpoint, *Exchange, *Channel) error
	OnClosed func(*Endpoint, *Exchange, *Channel) error
}

func (h *EndpointHooks) Register(hook EndpointHook) {
	h.hooks = append(h.hooks, hook)
}

func (h *ExchangeHooks) Register(hook ExchangeHook) {
	h.hooks = append(h.hooks, hook)
}

func (h *ChannelHooks) Register(hook ChannelHook) {
	h.hooks = append(h.hooks, hook)
}

func (h *EndpointHooks) trigger(f func(EndpointHook) error) error {
	for _, i := range h.hooks {
		err := f(i)
		if err == ErrStopPropagation {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *ExchangeHooks) trigger(f func(ExchangeHook) error) error {
	for _, i := range h.hooks {
		err := f(i)
		if err == ErrStopPropagation {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *ChannelHooks) trigger(f func(ChannelHook) error) error {
	for _, i := range h.hooks {
		err := f(i)
		if err == ErrStopPropagation {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *EndpointHooks) NetChanged(up, down []net.Addr) error {
	return s.trigger(func(o EndpointHook) error {
		if o.OnNetChanged == nil {
			return nil
		}
		return o.OnNetChanged(s.endpoint, up, down)
	})
}

func (s *EndpointHooks) DropPacket(msg []byte, conn net.Conn, reason error) error {
	return s.trigger(func(o EndpointHook) error {
		if o.OnDropPacket == nil {
			return nil
		}
		return o.OnDropPacket(s.endpoint, msg, conn, reason)
	})
}

func (s *ExchangeHooks) SessionReset() error {
	return s.trigger(func(o ExchangeHook) error {
		if o.OnSessionReset == nil {
			return nil
		}
		return o.OnSessionReset(s.endpoint, s.exchange)
	})
}

func (s *ExchangeHooks) Opened() error {
	return s.trigger(func(o ExchangeHook) error {
		if o.OnOpened == nil {
			return nil
		}
		return o.OnOpened(s.endpoint, s.exchange)
	})
}

func (s *ExchangeHooks) Closed(reason error) error {
	return s.trigger(func(o ExchangeHook) error {
		if o.OnClosed == nil {
			return nil
		}
		return o.OnClosed(s.endpoint, s.exchange, reason)
	})
}

func (s *ExchangeHooks) DropPacket(msg []byte, pipe *Pipe, reason error) error {
	return s.trigger(func(o ExchangeHook) error {
		if o.OnDropPacket == nil {
			return nil
		}
		return o.OnDropPacket(s.endpoint, s.exchange, msg, pipe, reason)
	})
}

func (s *ChannelHooks) Opened() error {
	return s.trigger(func(o ChannelHook) error {
		if o.OnOpened == nil {
			return nil
		}
		return o.OnOpened(s.endpoint, s.exchange, s.channel)
	})
}

func (s *ChannelHooks) Closed() error {
	return s.trigger(func(o ChannelHook) error {
		if o.OnClosed == nil {
			return nil
		}
		return o.OnClosed(s.endpoint, s.exchange, s.channel)
	})
}

package e3x

import (
	"errors"
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
}

type ExchangeHook struct {
	OnOpened func(*Endpoint, *Exchange) error
	OnClosed func(*Endpoint, *Exchange, error) error
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

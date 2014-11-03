package e3x

import (
	"fmt"
)

var (
	_ Event = (*ExchangeOpenedEvent)(nil)
	_ Event = (*ExchangeClosedEvent)(nil)
	_ Event = (*ChannelOpenedEvent)(nil)
	_ Event = (*ChannelClosedEvent)(nil)
)

type Event interface {
	String() string
}

type ExchangeOpenedEvent struct {
	Exchange *Exchange
}

type ExchangeClosedEvent struct {
	Exchange *Exchange
	Reason   error
}

type ChannelOpenedEvent struct {
	channel *Channel
}

type ChannelClosedEvent struct {
	channel *Channel
}

func (e *ExchangeOpenedEvent) String() string {
	return fmt.Sprintf("exchange opened: %s", e.Exchange)
}

func (e *ExchangeClosedEvent) String() string {
	if e.Reason == nil {
		return fmt.Sprintf("exchange closed: %s", e.Exchange)
	}
	return fmt.Sprintf("exchange closed: %s (reason=%s)", e.Exchange, e.Reason)
}

func (e *ChannelOpenedEvent) String() string {
	return fmt.Sprintf("channel opened: %s %s %d", e.channel.hashname, e.channel.typ, e.channel.id)
}

func (e *ChannelClosedEvent) String() string {
	return fmt.Sprintf("channel closed: %s %s %d", e.channel.hashname, e.channel.typ, e.channel.id)
}

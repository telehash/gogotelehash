package e3x

import (
	"fmt"

	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var (
	_ events.E = (*ExchangeOpenedEvent)(nil)
	_ events.E = (*ExchangeClosedEvent)(nil)
	_ events.E = (*ChannelOpenedEvent)(nil)
	_ events.E = (*ChannelClosedEvent)(nil)
)

type ExchangeOpenedEvent struct {
	Hashname  hashname.H
	Initiator bool
}

type ExchangeClosedEvent struct {
	Hashname hashname.H
	Reason   error
}

type ChannelOpenedEvent struct {
	channel *Channel
}

type ChannelClosedEvent struct {
	channel *Channel
}

func (e *ExchangeOpenedEvent) String() string {
	return fmt.Sprintf("exchange opened: %s (initiator=%v)", e.Hashname, e.Initiator)
}

func (e *ExchangeClosedEvent) String() string {
	if e.Reason == nil {
		return fmt.Sprintf("exchange closed: %s (reason=expired)", e.Hashname)
	} else {
		return fmt.Sprintf("exchange closed: %s (reason=%s)", e.Hashname, e.Reason)
	}
}

func (e *ChannelOpenedEvent) String() string {
	return fmt.Sprintf("channel opened: %s %s %d", e.channel.hashname, e.channel.typ, e.channel.id)
}

func (e *ChannelClosedEvent) String() string {
	return fmt.Sprintf("channel closed: %s %s %d", e.channel.hashname, e.channel.typ, e.channel.id)
}

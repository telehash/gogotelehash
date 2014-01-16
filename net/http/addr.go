package http

import (
	"errors"
	"fmt"
	th "github.com/telehash/gogotelehash/net"
)

var (
	ErrInvalidHTTPAddress = errors.New("invalid HTTP address")
)

type Addr struct {
	URL string
}

func (a *Addr) NeedNatHolePunching() bool {
	return false
}

func (a *Addr) PublishWithConnect() bool {
	return false
}

func (a *Addr) PublishWithPath() bool {
	return true
}

func (a *Addr) PublishWithPeer() bool {
	return true
}

func (a *Addr) PublishWithSeek() bool {
	return false
}

func (a *Addr) String() string {
	return fmt.Sprintf("url=%s", a.URL)
}

func (a *Addr) DefaultPriority() int {
	return 2
}

func (a *Addr) EqualTo(other th.Addr) bool {
	if b, ok := other.(*Addr); ok {
		return a.URL == b.URL
	}
	return false
}

type internal_addr struct {
	SessionID string
}

func (a *internal_addr) NeedNatHolePunching() bool {
	return false
}

func (a *internal_addr) PublishWithConnect() bool {
	return false
}

func (a *internal_addr) PublishWithPath() bool {
	return false
}

func (a *internal_addr) PublishWithPeer() bool {
	return false
}

func (a *internal_addr) PublishWithSeek() bool {
	return false
}

func (a *internal_addr) DefaultPriority() int {
	return 2
}

func (a *internal_addr) String() string {
	return fmt.Sprintf("session=%s", a.SessionID)
}

func (a *internal_addr) EqualTo(other th.Addr) bool {
	if b, ok := other.(*internal_addr); ok {
		return a.SessionID == b.SessionID
	}
	return false
}

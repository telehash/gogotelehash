package net

type Addr interface {
	SeekString() string

	PublishWithSeek() bool
	PublishWithPath() bool
	PublishWithPeer() bool
	PublishWithConnect() bool
	NeedNatHolePunching() bool

	DefaultPriority() int

	EqualTo(other Addr) bool
}

package net

type Addr interface {
	PublishWithSeek() bool
	PublishWithPath() bool
	PublishWithPeer() bool
	PublishWithConnect() bool
	NeedNatHolePunching() bool

	DefaultPriority() int

	EqualTo(other Addr) bool
	String() string
}

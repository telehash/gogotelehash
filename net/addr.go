package net

type Addr interface {
	SeekString() string

	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error

	PublishWithSeek() bool
	PublishWithPath() bool
	PublishWithPeer() bool
	PublishWithConnect() bool
	NeedNatHolePunching() bool

	DefaultPriority() int

	EqualTo(other Addr) bool
}

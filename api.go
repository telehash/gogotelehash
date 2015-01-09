package telehash

import (
	"encoding/json"
	"net"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/transports"

	"github.com/telehash/gogotelehash/internal/modules/bridge"
	"github.com/telehash/gogotelehash/internal/modules/paths"
)

type (
	EndpointOption e3x.EndpointOption
	Endpoint       struct{ inner *e3x.Endpoint }
	Exchange       struct{ inner *e3x.Exchange }
	Listener       struct{ inner *e3x.Listener }
	Channel        struct{ inner *e3x.Channel }
	Hashname       hashname.H
	Identity       struct{ inner *e3x.Identity }
	Identifier     e3x.Identifier
	Packet         lob.Packet
)

func Transport(config transports.Config) EndpointOption {
	return EndpointOption(e3x.Transport(config))
}

func Open(options ...EndpointOption) (*Endpoint, error) {
	innerOptions := make([]e3x.EndpointOption, len(options)+10)

	innerOptions = append(innerOptions, paths.Module())
	innerOptions = append(innerOptions, bridge.Module(bridge.Config{}))

	for i, option := range options {
		innerOptions[i] = e3x.EndpointOption(option)
	}

	inner, err := e3x.Open(innerOptions...)
	if err != nil {
		return nil, err
	}

	return &Endpoint{inner: inner}, nil
}

func (e *Endpoint) Close() error {
	return e.inner.Close()
}

func (e *Endpoint) Listen(typ string, reliable bool) *Listener {
	return &Listener{e.inner.Listen(typ, reliable)}
}

func (e *Endpoint) LocalIdentity() (*Identity, error) {
	inner, err := e.inner.LocalIdentity()
	if err != nil {
		return nil, err
	}

	return &Identity{inner}, nil
}

func (e *Endpoint) Dial(identifier Identifier) (*Exchange, error) {
	inner, err := e.inner.Dial(e3x.Identifier(identifier))
	if err != nil {
		return nil, err
	}

	return &Exchange{inner}, nil
}

func (e *Endpoint) Open(identifier Identifier, typ string, reliable bool) (*Channel, error) {
	inner, err := e.inner.Open(identifier, typ, reliable)
	if err != nil {
		return nil, err
	}

	return &Channel{inner}, nil
}

func (x *Exchange) RemoteIdentity() *Identity {
	return &Identity{x.inner.RemoteIdentity()}
}

func (x *Exchange) Open(typ string, reliable bool) (*Channel, error) {
	inner, err := x.inner.Open(typ, reliable)
	if err != nil {
		return nil, err
	}

	return &Channel{inner}, nil
}

func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *Listener) Accept() (net.Conn, error) {
	return l.inner.Accept()
}

func (l *Listener) AcceptChannel() (*Channel, error) {
	inner, err := l.inner.AcceptChannel()
	if err != nil {
		return nil, err
	}

	return &Channel{inner}, nil
}

func (l *Listener) Close() error {
	return l.inner.Close()
}

func (c *Channel) LocalAddr() net.Addr {
	return c.inner.LocalAddr()
}

func (c *Channel) RemoteAddr() net.Addr {
	return c.inner.RemoteAddr()
}

func (c *Channel) WritePacket(pkt *Packet) error {
	return c.inner.WritePacket((*lob.Packet)(pkt))
}

func (c *Channel) Write(b []byte) (int, error) {
	return c.inner.Write(b)
}

func (c *Channel) ReadPacket() (*Packet, error) {
	inner, err := c.inner.ReadPacket()
	if err != nil {
		return nil, err
	}
	return (*Packet)(inner), nil
}

func (c *Channel) Read(b []byte) (int, error) {
	return c.inner.Read(b)
}

func (c *Channel) SetDeadline(d time.Time) error {
	return c.inner.SetDeadline(d)
}

func (c *Channel) SetReadDeadline(d time.Time) error {
	return c.inner.SetReadDeadline(d)
}

func (c *Channel) SetWriteDeadline(d time.Time) error {
	return c.inner.SetWriteDeadline(d)
}

func (c *Channel) Errorf(format string, args ...interface{}) error {
	return c.inner.Errorf(format, args...)
}

func (c *Channel) Error(err error) error {
	return c.inner.Error(err)
}

func (c *Channel) Close() error {
	return c.inner.Close()
}

func (i *Identity) Hashname() Hashname {
	return Hashname(i.inner.Hashname())
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.inner)
}

func (i *Identity) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &i.inner)
}

func (i *Identity) String() string {
	return i.inner.String()
}

func (i *Identity) Identify(e *e3x.Endpoint) (*e3x.Identity, error) {
	return i.inner.Identify(e)
}

func (p *Packet) Header() *lob.Header {
	return (*lob.Packet)(p).Header()
}

func (p *Packet) Free() {
	(*lob.Packet)(p).Free()
}

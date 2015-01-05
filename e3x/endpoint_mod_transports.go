package e3x

import (
	"net"

	"github.com/telehash/gogotelehash/transports"
)

// Transports exposes the Wrap method
type Transports interface {
	// Wrap must be called durring a Module.Init call. The existing endpoint
	// transport will be passed to and a valid transport must be returned.
	// Only use this module when you know what you are doeing.
	Wrap(f func(transports.Config) transports.Config)

	// LocalAddresses returns the list of discovered local addresses
	LocalAddresses() []net.Addr
}

// TransportsFromEndpoint returns the Transports module for Endpoint.
func TransportsFromEndpoint(e *Endpoint) Transports {
	mod := e.Module(modTransportsKey)
	if mod == nil {
		return nil
	}
	return mod.(*modTransports)
}

const modTransportsKey = pivateModKey("transports")

type modTransports struct {
	e *Endpoint
}

func (mod *modTransports) Init() error  { return nil }
func (mod *modTransports) Start() error { return nil }
func (mod *modTransports) Stop() error  { return nil }

func (mod *modTransports) Wrap(f func(transports.Config) transports.Config) {
	mod.e.transportConfig = f(mod.e.transportConfig)
}

func (mod *modTransports) LocalAddresses() []net.Addr {
	return mod.e.transport.Addrs()
}

package e3x

import (
	"github.com/telehash/gogotelehash/transports"
)

type Transports interface {
	Wrap(func(transports.Config) transports.Config)
}

func TransportsFromEndpoint(e *Endpoint) Transports {
	mod := e.Module(modTransportsKey)
	if mod == nil {
		return nil
	}
	return mod.(*modTransports)
}

const modTransportsKey = modTransportsKeyType("transports")

type modTransportsKeyType string

type modTransports struct {
	e *Endpoint
}

func (mod *modTransports) Init() error  { return nil }
func (mod *modTransports) Start() error { return nil }
func (mod *modTransports) Stop() error  { return nil }

func (m *modTransports) Wrap(f func(transports.Config) transports.Config) {
	m.e.transportConfig = f(m.e.transportConfig)
}

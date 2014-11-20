// Package netwatch monitors the local networks available and notifies the
// interested components of any changes.
package netwatch

import (
	"fmt"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/logs"
)

const (
	moduleKey = "netwatch"
	interval  = 1 * time.Second
)

var (
	_ e3x.Module = (*module)(nil)
	_ e3x.Event  = (*ChangeEvent)(nil)
)

type module struct {
	endpoint  *e3x.Endpoint
	log       *logs.Logger
	observers e3x.Observers
	transport e3x.Transports
	timer     *time.Timer
	addresses []transports.Addr
}

func Module() func(*e3x.Endpoint) error {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, &module{endpoint: e})(e)
	}
}

type ChangeEvent struct {
	Up   []transports.Addr
	Down []transports.Addr
}

func (event *ChangeEvent) String() string {
	return fmt.Sprintf("Network change: up: %s down: %s", event.Up, event.Down)
}

func (mod *module) Init() error {
	mod.log = mod.endpoint.Log().Module("netwatch")
	mod.observers = e3x.ObserversFromEndpoint(mod.endpoint)
	mod.transport = e3x.TransportsFromEndpoint(mod.endpoint)
	return nil
}

func (mod *module) Start() error {
	mod.update()
	mod.timer = time.AfterFunc(interval, mod.update)
	return nil
}

func (mod *module) Stop() error {
	if mod.timer != nil {
		mod.timer.Stop()
		mod.timer = nil
	}
	return nil
}

func (mod *module) update() {
	if mod.timer != nil {
		mod.timer.Reset(interval)
	}

	var (
		addrs    = mod.transport.LocalAddresses()
		newAddrs []transports.Addr
		oldAddrs []transports.Addr
		update   []transports.Addr
	)

	// find new addresses
	for _, x := range addrs {
		var (
			found = false
			y     transports.Addr
		)

		for _, y = range mod.addresses {
			if transports.EqualAddr(x, y) {
				found = true
				break
			}
		}

		if !found {
			update = append(update, x)
			newAddrs = append(newAddrs, x)
		} else {
			update = append(update, y)
		}
	}

	// find old addresses
	for _, x := range mod.addresses {
		var (
			found = false
			y     transports.Addr
		)

		for _, y = range addrs {
			if transports.EqualAddr(x, y) {
				found = true
				break
			}
		}

		if !found {
			oldAddrs = append(newAddrs, x)
		} // else ignore
	}

	mod.addresses = update

	if len(newAddrs) > 0 || len(oldAddrs) > 0 {
		mod.observers.Trigger(&ChangeEvent{newAddrs, oldAddrs})
	}

	for _, addr := range oldAddrs {
		mod.log.Printf("Network down: %s", addr)
	}

	for _, addr := range newAddrs {
		mod.log.Printf("Network up: %s", addr)
	}
}

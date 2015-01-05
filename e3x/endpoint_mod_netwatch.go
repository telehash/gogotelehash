package e3x

import (
	"net"
	"time"

	"github.com/telehash/gogotelehash/transports"
)

const (
	modNetwatchKey = pivateModKey("netwatch")
	interval       = 1 * time.Second
)

var (
	_ Module = (*modNetwatch)(nil)
)

type modNetwatch struct {
	endpoint  *Endpoint
	timer     *time.Timer
	addresses []net.Addr
}

func (mod *modNetwatch) Init() error {
	return nil
}

func (mod *modNetwatch) Start() error {
	mod.update()
	mod.timer = time.AfterFunc(interval, mod.update)
	return nil
}

func (mod *modNetwatch) Stop() error {
	if mod.timer != nil {
		mod.timer.Stop()
		mod.timer = nil
	}
	return nil
}

func (mod *modNetwatch) update() {
	if mod.timer != nil {
		mod.timer.Reset(interval)
	}

	var (
		addrs    = mod.endpoint.transport.Addrs()
		newAddrs []net.Addr
		oldAddrs []net.Addr
		update   []net.Addr
	)

	// find new addresses
	for _, x := range addrs {
		var (
			found = false
			y     net.Addr
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
			y     net.Addr
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
		mod.endpoint.Hooks().NetChanged(newAddrs, oldAddrs)
	}
}

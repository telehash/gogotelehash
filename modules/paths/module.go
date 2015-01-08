// Package paths negotiates additional paths between two endpoints.
package paths

import (
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/transports"
)

const moduleKey = "paths"

type module struct {
	endpoint *e3x.Endpoint
	listener *e3x.Listener
}

func Module() e3x.EndpointOption {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, &module{endpoint: e})(e)
	}
}

func (mod *module) Init() error {
	mod.endpoint.Hooks().Register(e3x.EndpointHook{
		OnNetChanged: mod.onNetChange,
	})
	mod.endpoint.DefaultExchangeHooks().Register(e3x.ExchangeHook{
		OnOpened: mod.onNewLink,
	})

	mod.listener = mod.endpoint.Listen("path", false)
	return nil
}

func (mod *module) Start() error {
	go mod.handlePathRequests()
	return nil
}

func (mod *module) Stop() error {
	mod.listener.Close()
	return nil
}

func (mod *module) onNetChange(e *e3x.Endpoint, up, down []net.Addr) error {
	if len(up) == 0 {
		return nil
	}

	for _, x := range e.GetExchanges() {
		go mod.negotiatePaths(x)
	}

	return nil
}

func (mod *module) onNewLink(e *e3x.Endpoint, x *e3x.Exchange) error {
	go mod.negotiatePaths(x)
	return nil
}

func (mod *module) handlePathRequests() {
	for {
		c, err := mod.listener.AcceptChannel()
		if err == io.EOF {
			return
		}
		if err != nil {
			continue
		}
		go mod.handlePathRequest(c)
	}
}

func (mod *module) negotiatePaths(x *e3x.Exchange) {
	addrs := e3x.TransportsFromEndpoint(mod.endpoint).LocalAddresses()

	c, err := x.Open("path", false)
	if err != nil {
		return
	}
	defer c.Kill()

	c.SetDeadline(time.Now().Add(1 * time.Minute))

	pkt := &lob.Packet{}
	pkt.Header().Set("paths", addrs)
	if err := c.WritePacket(pkt); err != nil {
		return // ignore
	}

	for {
		_, err := c.ReadPacket()
		if err == io.EOF || err == e3x.ErrTimeout {
			return
		}
		if err != nil {
			return
		}
	}
}

func (mod *module) handlePathRequest(c *e3x.Channel) {
	defer c.Kill()

	pkt, err := c.ReadPacket()
	if err != nil {
		return // ignore
	}

	// decode paths known by peer and add them as candidates
	if header, found := pkt.Header().Get("paths"); found {
		data, err := json.Marshal(header)
		if err != nil {
			return // ignore
		}

		var entries []json.RawMessage
		err = json.Unmarshal(data, &entries)
		if err != nil {
			return // ignore
		}

		for _, entry := range entries {
			addr, err := transports.DecodeAddr(entry)
			if err != nil {
			}
			if err == nil {
				c.Exchange().AddPathCandidate(addr)
			}
		}
	}

	var pipes = c.Exchange().KnownPipes()

	for _, pipe := range pipes {
		pkt := &lob.Packet{}
		pkt.Header().Set("path", pipe.RemoteAddr())
		c.WritePacketTo(pkt, pipe)
	}
}

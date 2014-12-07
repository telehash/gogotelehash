// Package paths negotiates additional paths between two endpoints.
package paths

import (
	"encoding/json"
	"io"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/modules/netwatch"
	"github.com/telehash/gogotelehash/transports"
)

const moduleKey = "paths"

type module struct {
	endpoint *e3x.Endpoint
	listener *e3x.Listener
	mesh     mesh.Mesh
}

func Module() e3x.EndpointOption {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, &module{endpoint: e})(e)
	}
}

func (mod *module) Init() error {
	observers := e3x.ObserversFromEndpoint(mod.endpoint)
	observers.Register(mod.onNetChange)
	observers.Register(mod.onNewLink)

	mod.mesh = mesh.FromEndpoint(mod.endpoint)
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

func (mod *module) onNetChange(event *netwatch.ChangeEvent) {
	if len(event.Up) == 0 {
		return
	}

	for _, x := range mod.mesh.LinkedExchanges() {
		go mod.negotiatePaths(x)
	}
}

func (mod *module) onNewLink(event *mesh.LinkUpEvent) {
	mod.negotiatePaths(event.Exchange)
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
	defer e3x.ForgetterFromEndpoint(mod.endpoint).ForgetChannel(c)

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
	defer e3x.ForgetterFromEndpoint(mod.endpoint).ForgetChannel(c)

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

	var paths = c.Exchange().KnownPaths()

	for _, path := range paths {
		pkt := &lob.Packet{}
		pkt.Header().Set("path", path)
		c.WritePacketTo(pkt, path)
	}
}

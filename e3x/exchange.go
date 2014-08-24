package e3x

import (
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
)

type Endpoint struct {
	inbound      <-chan *lob.Packet // transports -> endpoint
	outboundLow  chan<- *lob.Packet // endpoint -> transports
	outboundHigh <-chan *lob.Packet // channels -> endpoint (-> transports)
	tokens       map[cipherset.Token]*exchange
	hashnames    map[hashname.H]*exchange
}

type exchange struct{}

func (e *Endpoint) Run() error {
	for {
		select {

		case pkt := <-e.inbound:
		// handle inbound packet

		case pkt := <-e.outboundHigh:
			// hanndle outbound packet

		}
	}
}

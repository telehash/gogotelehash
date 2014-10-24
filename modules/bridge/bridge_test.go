package bridge

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/fw"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
)

func TestBridge(t *testing.T) {
	// given:
	// A <-> B exchange
	// B <-> R exchange
	// A x-x R no exchange
	//
	// when:
	// R --> B route token from A->B to B
	// A --x B block A from contacting B (while adding R's addresses to the exchange A->B)
	//
	// then:
	// A and B should still be able to communicate.

	assert := assert.New(t)

	var blacklist []transports.Addr
	blacklistRule := func(p []byte, src transports.Addr) bool {
		if len(blacklist) == 0 {
			return true
		}

		for _, addr := range blacklist {
			if transports.EqualAddr(addr, src) {
				return false
			}
		}

		return true
	}

	A := e3x.New(randomKeys(0x1a, 0x3a), udp.Config{})
	B := e3x.New(randomKeys(0x1a, 0x3a), fw.Config{udp.Config{}, fw.RuleFunc(blacklistRule)})

	R := e3x.New(randomKeys(0x1a, 0x3a), udp.Config{})
	Register(R)
	bridge := FromEndpoint(R)

	A.AddHandler("ping", e3x.HandlerFunc(func(c *e3x.Channel) {
		defer c.Close()

		var (
			pkt   *lob.Packet
			err   error
			n     = 1
			first = true
		)

		for ; n > 0; n-- {
			pkt, err = c.ReadPacket()
			if err != nil {
				t.Logf("ping: error: %s", err)
				return
			}

			if first {
				n, _ = pkt.Header().GetInt("n")
			}

			err = c.WritePacket(&lob.Packet{})
			if err != nil {
				t.Logf("ping: error: %s", err)
				return
			}
		}
	}))

	registerEventLoggers(A, t)
	registerEventLoggers(B, t)
	registerEventLoggers(R, t)

	assert.NoError(A.Start())
	assert.NoError(B.Start())
	assert.NoError(R.Start())

	Aaddr, err := A.LocalAddr()
	assert.NoError(err)
	Baddr, err := B.LocalAddr()
	assert.NoError(err)
	Raddr, err := R.LocalAddr()
	assert.NoError(err)

	ABex, err := A.Dial(Baddr)
	assert.NoError(err)
	BRex, err := B.Dial(Raddr)
	assert.NoError(err)
	RBex, err := R.Dial(Baddr)
	assert.NoError(err)
	RAex, err := R.Dial(Aaddr)
	assert.NoError(err)

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	// blacklist A
	blacklist = append(blacklist, Aaddr.Addresses()...)
	log.Println("\x1B[32mblacklist:\x1B[0m", blacklist)

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	bridge.RouteToken(ABex.SenderToken(), RBex)
	bridge.RouteToken(ABex.ReceiverToken(), RAex)
	ABex.AddPathCandidate(BRex.ActivePath())

	time.Sleep(10 * time.Second)

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	{
		ch, err := B.Open(Aaddr, "ping", true)
		assert.NoError(err)

		for n := 10; n > 0; n-- {
			pkt := &lob.Packet{}
			pkt.Header().SetInt("n", n)
			err = ch.WritePacket(pkt)
			if err != nil {
				t.Logf("ping: error: %s", err)
				return
			}

			_, err = ch.ReadPacket()
			if err != nil {
				t.Logf("ping: error: %s", err)
				return
			}
		}

		ch.Close()
	}
}

func randomKeys(csids ...uint8) cipherset.Keys {
	keys := cipherset.Keys{}

	for _, csid := range csids {
		key, err := cipherset.GenerateKey(csid)
		if err != nil {
			panic(err)
		}
		keys[csid] = key
	}

	return keys
}

func registerEventLoggers(e *e3x.Endpoint, t *testing.T) {
	observers := e3x.ObserversFromEndpoint(e)
	observers.Register(func(e *e3x.ExchangeOpenedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *e3x.ExchangeClosedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *e3x.ChannelOpenedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *e3x.ChannelClosedEvent) { t.Logf("EVENT: %s", e.String()) })
}

package bridge

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/fw"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
)

var log = logs.Module("test")

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

	A, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}))
	assert.NoError(err)
	B, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(fw.Config{Config: udp.Config{}, Allow: fw.RuleFunc(blacklistRule)}))
	assert.NoError(err)

	R, err := e3x.Open(
		e3x.Log(nil),
		e3x.Transport(udp.Config{}),
		Module())
	assert.NoError(err)

	bridge := FromEndpoint(R)

	done := make(chan bool, 1)

	go func() {

		var (
			pkt   *lob.Packet
			err   error
			n     = 1
			first = true
		)

		defer func() { done <- true }()

		c, err := A.Listen("ping", true).AcceptChannel()
		defer c.Close()

		for ; n > 0; n-- {
			pkt, err = c.ReadPacket()
			if err != nil {
				t.Fatalf("ping: error: %s", err)
				return
			}

			if first {
				n, _ = pkt.Header().GetInt("n")
			}

			err = c.WritePacket(&lob.Packet{})
			if err != nil {
				t.Fatalf("ping: error: %s", err)
				return
			}
		}
	}()

	Aident, err := A.LocalIdentity()
	assert.NoError(err)
	Bident, err := B.LocalIdentity()
	assert.NoError(err)
	Rident, err := R.LocalIdentity()
	assert.NoError(err)

	ABex, err := A.Dial(Bident)
	assert.NoError(err)
	BRex, err := B.Dial(Rident)
	assert.NoError(err)
	RBex, err := R.Dial(Bident)
	assert.NoError(err)
	RAex, err := R.Dial(Aident)
	assert.NoError(err)

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	// blacklist A
	blacklist = append(blacklist, Aident.Addresses()...)
	log.Println("\x1B[32mblacklist:\x1B[0m", blacklist)

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	bridge.RouteToken(ABex.LocalToken(), RAex)
	bridge.RouteToken(ABex.RemoteToken(), RBex)
	ABex.AddPathCandidate(BRex.ActivePath())

	log.Println("\x1B[31m------------------------------------------------\x1B[0m")

	{
		ch, err := B.Open(Aident, "ping", true)
		assert.NoError(err)

		for n := 10; n > 0; n-- {
			pkt := &lob.Packet{}
			pkt.Header().SetInt("n", n)
			err = ch.WritePacket(pkt)
			if err != nil {
				t.Fatalf("ping: error: %s", err)
			}

			_, err = ch.ReadPacket()
			if err != nil {
				t.Fatalf("ping: error: %s", err)
			}
		}

		ch.Close()
	}

	<-done

	assert.NoError(A.Stop())
	assert.NoError(B.Stop())
	assert.NoError(R.Stop())
}

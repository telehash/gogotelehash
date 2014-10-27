package e3x

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/logs"

	_ "github.com/telehash/gogotelehash/e3x/cipherset/cs3a"
)

func TestBasicExchange(t *testing.T) {
	logs.ResetLogger()

	if testing.Short() {
		t.Skip("this is a long running test.")
	}

	var (
		assert    = assert.New(t)
		err       error
		observers = &modObservers{}

		A = struct {
			a *Ident
			t transports.Transport
			x *Exchange
		}{
			a: makeIdent("A"),
		}

		B = struct {
			a *Ident
			t transports.Transport
			x *Exchange
		}{
			a: makeIdent("B"),
		}
	)

	observers.Register(func(e *ExchangeOpenedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *ExchangeClosedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *ChannelOpenedEvent) { t.Logf("EVENT: %s", e.String()) })
	observers.Register(func(e *ChannelClosedEvent) { t.Logf("EVENT: %s", e.String()) })

	A.t, B.t = openPipeTransport("A", "B")

	A.x, err = newExchange(A.a, B.a, nil, cipherset.ZeroToken, A.t, observers, nil,
		logs.Module("e3x").From(A.a.Hashname()).To(B.a.Hashname()))
	assert.NoError(err)

	go pipeTransportReader(A.x, A.t)

	go func() {
		var (
			handshake cipherset.Handshake
			token     cipherset.Token
			err       error
			buf       = make([]byte, 64*1024)
			src       transports.Addr
			n         int
		)

		n, src, err = B.t.ReadMessage(buf)
		assert.NoError(err)
		buf = buf[:n]

		// detect handshake
		assert.Equal(0, buf[0])
		assert.Equal(1, buf[1])
		assert.Equal(0x3a, buf[2])
		handshake, err = cipherset.DecryptHandshake(0x3a, B.a.keys[0x3a], buf[3:])
		if assert.NoError(err) {
			token = cipherset.ExtractToken(buf)

			B.x, err = newExchange(B.a, nil, handshake, token, B.t, observers, nil,
				logs.Module("e3x").From(B.a.Hashname()).To(A.a.Hashname()))
			assert.NoError(err)

			B.x.received(opRead{buf, src, nil})

			go pipeTransportReader(B.x, B.t)
		}
	}()

	A.x.waitDone()
	B.x.waitDone()
}

func pipeTransportReader(x *Exchange, r transports.Transport) {
	for {
		var (
			err error
			buf = make([]byte, 64*1024)
			src transports.Addr
			n   int
		)

		n, src, err = r.ReadMessage(buf)
		if err == transports.ErrClosed {
			return
		}

		x.received(opRead{buf[:n], src, err})
	}
}

package e3x

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports/mux"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

func with_two_endpoints(t *testing.T, f func(a, b *Endpoint)) {
	with_endpoint(t, func(a *Endpoint) {
		with_endpoint(t, func(b *Endpoint) {
			f(a, b)
		})
	})
}

func with_endpoint(t *testing.T, f func(e *Endpoint)) {
	var (
		err     error
		key     cipherset.Key
		e       *Endpoint
		cEvents = make(chan events.E)
		tc      = mux.Config{
			udp.Config{Network: "udp4"},
			udp.Config{Network: "udp6"},
		}
	)

	go events.Log(nil, cEvents)

	key, err = cipherset.GenerateKey(0x3a)
	require.NoError(t, err)
	require.NotNil(t, key)

	e = New(cipherset.Keys{0x3a: key}, tc)
	require.NotNil(t, e)

	e.Subscribe(cEvents)

	err = e.Start()
	require.NoError(t, err)

	defer func() {
		err = e.Stop()
		require.NoError(t, err)

		close(cEvents)
	}()

	f(e)
}

func TestBasicUnrealiable(t *testing.T) {
	var (
		assert = assert.New(t)
		c      *Channel
		x      MockExchange
		pkt    *lob.Packet
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetString("type", "ping")
		x.On("deliver_packet", pkt).Return(nil)

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetBool("end", true)
		x.On("deliver_packet", pkt).Return(nil)

		x.On("unregister_channel", uint32(0)).Return().Once()
	}

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", false, false,
		&x)

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	c.received_packet(&lob.Packet{Body: []byte("pong")})

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}

	pkt = &lob.Packet{}
	pkt.Header().SetBool("end", true)
	c.received_packet(pkt)

	err = c.Close()
	assert.NoError(err)

	x.AssertExpectations(t)
}

func TestBasicRealiable(t *testing.T) {
	var (
		assert = assert.New(t)
		c      *Channel
		x      MockExchange
		pkt    *lob.Packet
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		pkt.Header().SetString("type", "ping")
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("seq", 0)
		x.On("deliver_packet", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 0)
		x.On("deliver_packet", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 0)
		pkt.Header().SetUint32Slice("miss", []uint32{1})
		x.On("deliver_packet", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 1)
		x.On("deliver_packet", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("seq", 1)
		pkt.Header().SetBool("end", true)
		pkt.Header().SetInt("ack", 0)
		x.On("deliver_packet", pkt).Return(nil).Once()

		x.On("unregister_channel", uint32(0)).Return().Once()
	}

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", true, false,
		&x)

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt = &lob.Packet{Body: []byte("pong")}
	pkt.Header().SetUint32("seq", 0)
	pkt.Header().SetUint32("ack", 0)
	c.received_packet(pkt)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	if assert.NotNil(pkt) {
		assert.Equal("pong", string(pkt.Body))
	}

	go func() {
		time.Sleep(10 * time.Millisecond)

		pkt = &lob.Packet{}
		pkt.Header().SetBool("end", true)
		pkt.Header().SetUint32("seq", 1)
		pkt.Header().SetUint32("ack", 1)
		c.received_packet(pkt)
	}()

	err = c.Close()
	assert.NoError(err)

	x.AssertExpectations(t)
}

func TestPingPong(t *testing.T) {
	with_two_endpoints(t, func(A, B *Endpoint) {
		var (
			assert = assert.New(t)
			c      *Channel
			addr   *Addr
			pkt    *lob.Packet
			err    error
		)

		A.AddHandler("ping", HandlerFunc(func(c *Channel) {
			var (
				err error
			)

			defer c.Close()

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			if assert.NotNil(pkt) {
				assert.Equal("ping", string(pkt.Body))

				err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
				assert.NoError(err)
			}
		}))

		addr, err = A.LocalAddr()
		assert.NoError(err)

		c, err = B.Open(addr, "ping", false)
		assert.NoError(err)
		if assert.NotNil(c) {
			defer c.Close()

			err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
			assert.NoError(err)

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			if assert.NotNil(pkt) {
				assert.Equal("pong", string(pkt.Body))
			}
		}
	})
}

func TestPingPongReliable(t *testing.T) {
	with_two_endpoints(t, func(A, B *Endpoint) {
		var (
			assert = assert.New(t)
			c      *Channel
			addr   *Addr
			pkt    *lob.Packet
			err    error
		)

		A.AddHandler("ping", HandlerFunc(func(c *Channel) {
			var (
				err error
			)

			defer c.Close()

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			if assert.NotNil(pkt) {
				assert.Equal("ping", string(pkt.Body))

				err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
				assert.NoError(err)
			}
		}))

		addr, err = A.LocalAddr()
		assert.NoError(err)

		c, err = B.Open(addr, "ping", true)
		assert.NoError(err)
		if assert.NotNil(c) {

			err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
			assert.NoError(err)

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			if assert.NotNil(pkt) {
				assert.Equal("pong", string(pkt.Body))
			}

			err = c.Close()
			assert.NoError(err)
		}
	})
}

func TestFloodReliable(t *testing.T) {
	if testing.Short() {
		t.Skip("this is a long running test.")
	}

	with_two_endpoints(t, func(A, B *Endpoint) {
		var (
			assert = assert.New(t)
			c      *Channel
			addr   *Addr
			pkt    *lob.Packet
			err    error
		)

		A.AddHandler("flood", HandlerFunc(func(c *Channel) {
			var (
				err error
			)

			defer c.Close()

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			assert.NotNil(pkt)
			tracef("S> RX open")

			for i := 0; i < 1000000; i++ {
				pkt := &lob.Packet{}
				pkt.Header().SetInt("flood_id", i)
				err = c.WritePacket(pkt)
				assert.NoError(err)
				tracef("S> TX %d", i)
			}
		}))

		addr, err = A.LocalAddr()
		assert.NoError(err)

		c, err = B.Open(addr, "flood", true)
		assert.NoError(err)
		assert.NotNil(c)

		defer c.Close()

		err = c.WritePacket(&lob.Packet{})
		assert.NoError(err)
		tracef("C> TX open")

		lastId := -1
		for {
			pkt, err = c.ReadPacket()
			if err == io.EOF {
				break
			}
			assert.NoError(err)
			assert.NotNil(pkt)
			if err != nil {
				break
			}
			if pkt != nil {
				id, _ := pkt.Header().GetInt("flood_id")
				assert.True(lastId < id)
				lastId = id
				tracef("C> RX %d", id)
			}
		}
	})
}

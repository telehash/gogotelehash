package e3x

import (
	"io"
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/transports/inproc"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
)

func withTwoEndpoints(t testing.TB, f func(a, b *Endpoint)) {
	withEndpoint(t, func(a *Endpoint) {
		withEndpoint(t, func(b *Endpoint) {
			f(a, b)
		})
	})
}

func withEndpoint(t testing.TB, f func(e *Endpoint)) {
	var (
		err error
		e   *Endpoint
	)

	e, err = Open(
		Transport(mux.Config{
			udp.Config{Network: "udp4"},
			udp.Config{Network: "udp6"},
			inproc.Config{},
		}),
		Log(nil))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = e.Stop()

		if err != nil {
			t.Fatal(err)
		}
	}()

	f(e)
}

func TestBasicUnrealiable(t *testing.T) {
	logs.ResetLogger()

	var (
		assert = assert.New(t)
		c      *Channel
		x      MockExchange
		pkt    *lob.Packet
		hdr    *lob.Header
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.Type, hdr.HasType = "ping", true
		x.On("deliverPacket", pkt).Return(nil)

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.End, hdr.HasEnd = true, true
		x.On("deliverPacket", pkt).Return(nil)

		x.On("unregisterChannel", uint32(0)).Return().Once()
	}

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", false, false,
		&x)

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	c.receivedPacket(&lob.Packet{Body: []byte("pong")})

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}

	pkt = &lob.Packet{}
	hdr = pkt.Header()
	hdr.End, hdr.HasEnd = true, true
	c.receivedPacket(pkt)

	err = c.Close()
	assert.NoError(err)

	x.AssertExpectations(t)
}

func TestBasicRealiable(t *testing.T) {
	logs.ResetLogger()

	var (
		assert = assert.New(t)
		c      *Channel
		x      MockExchange
		pkt    *lob.Packet
		hdr    *lob.Header
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		hdr = pkt.Header()
		hdr.Type, hdr.HasType = "ping", true
		hdr.C, hdr.HasC = 0, true
		hdr.Seq, hdr.HasSeq = 1, true
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.Ack, hdr.HasAck = 1, true
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.Ack, hdr.HasAck = 1, true
		hdr.Miss, hdr.HasMiss = []uint32{1}, true
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.Ack, hdr.HasAck = 2, true
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.C, hdr.HasC = 0, true
		hdr.Seq, hdr.HasSeq = 2, true
		hdr.Ack, hdr.HasAck = 1, true
		hdr.End, hdr.HasEnd = true, true
		x.On("deliverPacket", pkt).Return(nil).Once()

		x.On("unregisterChannel", uint32(0)).Return().Once()
	}

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", true, false,
		&x)

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt = &lob.Packet{Body: []byte("pong")}
	hdr = pkt.Header()
	hdr.Seq, hdr.HasSeq = 1, true
	hdr.Ack, hdr.HasAck = 1, true
	c.receivedPacket(pkt)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	if assert.NotNil(pkt) {
		assert.Equal("pong", string(pkt.Body))
	}

	go func() {
		time.Sleep(10 * time.Millisecond)

		pkt = &lob.Packet{}
		hdr = pkt.Header()
		hdr.Seq, hdr.HasSeq = 2, true
		hdr.Ack, hdr.HasAck = 2, true
		hdr.End, hdr.HasEnd = true, true
		c.receivedPacket(pkt)
	}()

	err = c.Close()
	assert.NoError(err)

	x.AssertExpectations(t)
}

func TestPingPong(t *testing.T) {
	logs.ResetLogger()

	withTwoEndpoints(t, func(A, B *Endpoint) {
		var (
			assert = assert.New(t)
			c      *Channel
			ident  *Identity
			pkt    *lob.Packet
			err    error
		)

		go func() {
			c, err := A.Listen("ping", false).AcceptChannel()

			if assert.NoError(err) && assert.NotNil(c) {
				defer c.Close()

				pkt, err = c.ReadPacket()
				if assert.NoError(err) && assert.NotNil(pkt) {
					assert.Equal("ping", string(pkt.Body))

					err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
					assert.NoError(err)
				}
			}
		}()

		ident, err = A.LocalIdentity()
		assert.NoError(err)

		c, err = B.Open(ident, "ping", false)
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
	logs.ResetLogger()

	withTwoEndpoints(t, func(A, B *Endpoint) {
		var (
			assert = assert.New(t)
			c      *Channel
			ident  *Identity
			pkt    *lob.Packet
			err    error
		)

		go func() {
			c, err := A.Listen("ping", true).AcceptChannel()
			if assert.NoError(err) && assert.NotNil(c) {
				defer c.Close()

				pkt, err = c.ReadPacket()
				if assert.NoError(err) && assert.NotNil(pkt) {
					assert.Equal("ping", string(pkt.Body))

					err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
					assert.NoError(err)
				}
			}
		}()

		ident, err = A.LocalIdentity()
		assert.NoError(err)

		c, err = B.Open(ident, "ping", true)
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

	withTwoEndpoints(t, func(A, B *Endpoint) {
		A.setOptions(DisableLog())
		B.setOptions(DisableLog())

		var (
			assert = assert.New(t)
			c      *Channel
			ident  *Identity
			pkt    *lob.Packet
			err    error
		)

		go func() {
			c, err := A.Listen("flood", true).AcceptChannel()
			if assert.NoError(err) && assert.NotNil(c) {
				defer c.Close()

				pkt, err = c.ReadPacket()
				assert.NoError(err)
				assert.NotNil(pkt)

				for i := 0; i < 1000000; i++ {
					pkt := &lob.Packet{}
					pkt.Header().SetInt("flood_id", i)
					err = c.WritePacket(pkt)
					assert.NoError(err)
				}
			}
		}()

		ident, err = A.LocalIdentity()
		assert.NoError(err)

		c, err = B.Open(ident, "flood", true)
		assert.NoError(err)
		assert.NotNil(c)

		defer c.Close()

		err = c.WritePacket(&lob.Packet{})
		assert.NoError(err)

		lastID := -1
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
				assert.True(lastID < id)
				lastID = id
			}
		}
	})
}

func BenchmarkReadWrite(b *testing.B) {
	logs.ResetLogger()

	withTwoEndpoints(b, func(A, B *Endpoint) {
		A.setOptions(DisableLog())
		B.setOptions(DisableLog())

		var (
			c     *Channel
			ident *Identity
			pkt   *lob.Packet
			err   error
		)

		b.ResetTimer()

		go func() {
			c, err := A.Listen("flood", true).AcceptChannel()
			if err != nil {
				b.Fatal(err)
			}

			defer c.Close()

			pkt, err = c.ReadPacket()
			if err != nil {
				b.Fatal(err)
			}

			for i := 0; i < b.N; i++ {
				pkt := &lob.Packet{Body: []byte("Hello World!")}
				err = c.WritePacket(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		}()

		ident, err = A.LocalIdentity()
		if err != nil {
			b.Fatal(err)
		}

		c, err = B.Open(ident, "flood", true)
		if err != nil {
			b.Fatal(err)
		}

		defer c.Close()

		err = c.WritePacket(&lob.Packet{})
		if err != nil {
			b.Fatal(err)
		}

		for {
			pkt, err = c.ReadPacket()
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			pkt.Free()
		}

		b.StopTimer()
	})
}

func BenchmarkChannels(b *testing.B) {
	logs.ResetLogger()

	var (
		ping = []byte("ping")
		pong = []byte("pong")
	)

	client := func(x *Exchange) {
		c, err := x.Open("ping", false)
		if err != nil {
			b.Fatal(err)
		}

		defer c.Close()

		pkt := &lob.Packet{Body: ping}
		err = c.WritePacket(pkt)
		if err != nil {
			b.Fatal(err)
		}

		pkt, err = c.ReadPacket()
		if err != nil {
			b.Fatal(err)
		}
		pkt.Free()
	}

	server := func(c *Channel) {
		defer c.Close()

		pkt, err := c.ReadPacket()
		if err != nil {
			b.Fatal(err)
		}
		pkt.Free()

		pkt = &lob.Packet{Body: pong}
		err = c.WritePacket(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}

	accept := func(l *Listener) {
		for {
			c, err := l.AcceptChannel()
			if err == io.EOF {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			go server(c)
		}
	}

	withTwoEndpoints(b, func(A, B *Endpoint) {
		A.setOptions(DisableLog())
		B.setOptions(DisableLog())

		var (
			ident *Identity
			err   error
		)

		b.ResetTimer()

		l := A.Listen("ping", false)
		defer l.Close()
		go accept(l)

		ident, err = A.LocalIdentity()
		if err != nil {
			b.Fatal(err)
		}

		x, err := B.Dial(ident)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			client(x)
		}

		b.StopTimer()
	})
}

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
		tc  = mux.Config{
			udp.Config{Network: "udp4"},
			udp.Config{Network: "udp6"},
			inproc.Config{},
		}
	)

	e = New(nil, tc)
	if e == nil {
		t.Fatalf("expected e (*Endpoint) not to be nil")
	}

	err = e.Start()
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
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetString("type", "ping")
		x.On("deliverPacket", pkt).Return(nil)

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetBool("end", true)
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
	pkt.Header().SetBool("end", true)
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
		err    error
	)

	{ // mock
		pkt = &lob.Packet{Body: []byte("ping")}
		pkt.Header().SetString("type", "ping")
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("seq", 1)
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 1)
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 1)
		pkt.Header().SetUint32Slice("miss", []uint32{1})
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("ack", 2)
		x.On("deliverPacket", pkt).Return(nil).Once()

		pkt = &lob.Packet{}
		pkt.Header().SetInt("c", 0)
		pkt.Header().SetInt("seq", 2)
		pkt.Header().SetBool("end", true)
		pkt.Header().SetInt("ack", 1)
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
	pkt.Header().SetUint32("seq", 1)
	pkt.Header().SetUint32("ack", 1)
	c.receivedPacket(pkt)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	if assert.NotNil(pkt) {
		assert.Equal("pong", string(pkt.Body))
	}

	go func() {
		time.Sleep(10 * time.Millisecond)

		pkt = &lob.Packet{}
		pkt.Header().SetBool("end", true)
		pkt.Header().SetUint32("seq", 2)
		pkt.Header().SetUint32("ack", 2)
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
	logs.DisableLogger()

	if testing.Short() {
		t.Skip("this is a long running test.")
	}

	withTwoEndpoints(t, func(A, B *Endpoint) {
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
	logs.DisableModule("e3x.tx")

	withTwoEndpoints(b, func(A, B *Endpoint) {
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
				pkt := &lob.Packet{}
				pkt.Header().SetInt("flood_id", i)
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
		}

		b.StopTimer()
	})
}

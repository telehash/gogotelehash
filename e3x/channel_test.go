package e3x

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/transports/inproc"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
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

	tr := mux.Config{
		inproc.Config{},
	}

	if os.Getenv("UDP_TRANSPORT") != "false" {
		tr = append(tr,
			udp.Config{Network: "udp4"})
		tr = append(tr,
			udp.Config{Network: "udp6"})
	}

	e, err = Open(
		Transport(tr),
		Log(nil))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = e.Close()

		if err != nil {
			t.Fatal(err)
		}
	}()

	f(e)
}

func TestPingPong(t *testing.T) {
	// t.Parallel()
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

			c.SetDeadline(time.Now().Add(10 * time.Second))

			if assert.NoError(err) && assert.NotNil(c) {
				defer c.Close()

				pkt, err = c.ReadPacket()
				if assert.NoError(err) && assert.NotNil(pkt) {
					assert.Equal("ping", string(pkt.Body(nil)))

					err = c.WritePacket(lob.New([]byte("pong")))
					assert.NoError(err)
				}
			}
		}()

		ident = A.LocalIdentity()

		c, err = B.Open(ident, "ping", false)
		assert.NoError(err)
		if assert.NotNil(c) {
			defer c.Close()

			c.SetDeadline(time.Now().Add(10 * time.Second))

			err = c.WritePacket(lob.New([]byte("ping")))
			assert.NoError(err)

			pkt, err = c.ReadPacket()
			if assert.NoError(err) && assert.NotNil(pkt) {
				assert.Equal("pong", string(pkt.Body(nil)))
			}
		}
	})
}

func TestPingPongReliable(t *testing.T) {
	// t.Parallel()
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
					assert.Equal("ping", string(pkt.Body(nil)))

					err = c.WritePacket(lob.New([]byte("pong")))
					assert.NoError(err)
				}
			}
		}()

		ident = A.LocalIdentity()

		c, err = B.Open(ident, "ping", true)
		assert.NoError(err)
		if assert.NotNil(c) {

			err = c.WritePacket(lob.New([]byte("ping")))
			assert.NoError(err)

			pkt, err = c.ReadPacket()
			assert.NoError(err)
			if assert.NotNil(pkt) {
				assert.Equal("pong", string(pkt.Body(nil)))
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

				for i := 0; i < 100000; i++ {
					pkt := lob.New(nil)
					pkt.Header().SetInt("flood_id", i)
					err = c.WritePacket(pkt)
					assert.NoError(err)
				}
			}
		}()

		ident = A.LocalIdentity()

		c, err = B.Open(ident, "flood", true)
		assert.NoError(err)
		assert.NotNil(c)

		defer c.Close()

		err = c.WritePacket(lob.New(nil))
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

func BenchmarkReadWriteReliable(b *testing.B) {
	defer dumpExpVar(b)
	logs.ResetLogger()

	withTwoEndpoints(b, func(A, B *Endpoint) {
		A.setOptions(DisableLog())
		B.setOptions(DisableLog())

		var (
			c     *Channel
			ident *Identity
			pkt   *lob.Packet
			err   error
			body  = bytes.Repeat([]byte{'x'}, 1300)
		)

		b.SetBytes(int64(len(body)))
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
				pkt := lob.New(body)
				err = c.WritePacket(pkt)
				if err != nil {
					b.Fatal(err)
				}
			}
		}()

		ident = A.LocalIdentity()

		c, err = B.Open(ident, "flood", true)
		if err != nil {
			b.Fatal(err)
		}

		defer c.Close()

		err = c.WritePacket(lob.New(nil))
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

func BenchmarkReadWriteUnreliable(b *testing.B) {
	defer dumpExpVar(b)
	logs.ResetLogger()

	withTwoEndpoints(b, func(A, B *Endpoint) {
		A.setOptions(DisableLog())
		B.setOptions(DisableLog())

		var (
			c     *Channel
			ident *Identity
			pkt   *lob.Packet
			err   error
			body  = bytes.Repeat([]byte{'x'}, 1300)
		)

		b.SetBytes(int64(len(body)))
		b.ResetTimer()

		go func() {
			c, err := A.Listen("flood", false).AcceptChannel()
			if err != nil {
				b.Fatal(err)
			}

			defer c.Close()

			pkt, err = c.ReadPacket()
			if err != nil {
				b.Fatal(err)
			}

			for i := 0; i < b.N; i++ {
				pkt := lob.New(body)
				err = c.WritePacket(pkt)
				if err != nil {
					b.Fatal(err)
				}

				// Give the other go routines some room to breath when GOMAXPROCS=1
				runtime.Gosched()
			}
		}()

		ident = A.LocalIdentity()

		c, err = B.Open(ident, "flood", false)
		if err != nil {
			b.Fatal(err)
		}

		defer c.Close()

		err = c.WritePacket(lob.New(nil))
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
	defer dumpExpVar(b)
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

		pkt := lob.New(ping)
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

		pkt = lob.New(pong)
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

		ident = A.LocalIdentity()

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

func BenchmarkChannelsReliable(b *testing.B) {
	defer dumpExpVar(b)
	logs.ResetLogger()

	var (
		ping = []byte("ping")
		pong = []byte("pong")
	)

	client := func(x *Exchange) {
		c, err := x.Open("ping", true)
		if err != nil {
			b.Fatal(err)
		}

		defer c.Close()

		pkt := lob.New(ping)
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

		pkt = lob.New(pong)
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

		l := A.Listen("ping", true)
		defer l.Close()
		go accept(l)

		ident = A.LocalIdentity()

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

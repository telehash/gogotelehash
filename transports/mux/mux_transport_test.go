package mux

import (
	"bytes"
	"net"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/udp"
)

func TestManagerWithoutTransports(t *testing.T) {
	assert := assert.New(t)

	var (
		c   = Config{}
		tr  transports.Transport
		err error
	)

	tr, err = c.Open()
	if assert.NoError(err) && assert.NotNil(tr) {

		err = tr.Close()
		assert.NoError(err)
	}
}

func TestManagerWithOneTransport(t *testing.T) {
	assert := assert.New(t)

	var (
		c   = Config{udp.Config{}}
		tr  transports.Transport
		err error
	)

	tr, err = c.Open()
	if assert.NoError(err) && assert.NotNil(tr) {
		t.Logf("addrs=%v", tr.Addrs())

		err = tr.Close()
		assert.NoError(err)
	}
}

func Benchmark(b *testing.B) {
	A, err := Config{udp.Config{}}.Open()
	if err != nil {
		b.Fatal(err)
	}
	defer A.Close()

	B, err := Config{udp.Config{}}.Open()
	if err != nil {
		b.Fatal(err)
	}
	defer B.Close()

	var (
		msg = bytes.Repeat([]byte{'x'}, 1450)
		dst = B.Addrs()[0]
		out [1500]byte
		w   net.Conn
		r   net.Conn
	)

	{ // setup
		w, err = A.Dial(dst)
		if err != nil {
			b.Fatal(err)
		}
		if w == nil {
			b.Fatal("w should not be nil")
		}

		_, err = w.Write(msg)
		if err != nil {
			b.Fatal(err)
		}

		r, err = B.Accept()
		if err != nil {
			b.Fatal(err)
		}
		if r == nil {
			b.Fatal("r should not be nil")
		}

		n, err := r.Read(out[:])
		if err != nil {
			b.Fatal(err)
		}

		if !bytes.Equal(out[:n], msg) {
			b.Fatalf("invalid message")
		}
	}

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()

	for i := 0; i < b.N; i += 2 {
		_, err = w.Write(msg)
		if err != nil {
			b.Fatal(err)
		}

		n, err := r.Read(out[:])
		if err != nil {
			b.Fatal(err)
		}

		if !bytes.Equal(out[:n], msg) {
			b.Fatalf("invalid message")
		}
	}
}

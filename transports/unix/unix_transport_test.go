package unix

import (
	"bytes"
	"net"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
)

func TestLocalAddresses(t *testing.T) {
	assert := assert.New(t)
	var tab = []Config{
		{},
		{Name: "/tmp/telehash-test.sock"},
		{Name: "/tmp/telehash-test.sock", Mode: 0755},
		{Mode: 0755},
	}

	for _, factory := range tab {
		trans, err := factory.Open()
		if assert.NoError(err) && assert.NotNil(trans) {
			addrs := trans.Addrs()
			assert.NotEmpty(addrs)

			t.Logf("factory=%v addrs=%v", factory, addrs)
			err = trans.Close()
			assert.NoError(err)
		}
	}
}

func Benchmark(b *testing.B) {
	A, err := Config{}.Open()
	if err != nil {
		b.Fatal(err)
	}
	defer A.Close()

	B, err := Config{}.Open()
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

		_, err = w.Write(msg)
		if err != nil {
			b.Fatal(err)
		}

		r, err = B.Accept()
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

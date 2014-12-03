package udp

import (
	"bytes"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
)

func TestLocalAddresses(t *testing.T) {
	assert := assert.New(t)
	var tab = []Config{
		{},
		{Network: "udp4", Addr: "127.0.0.1:0"},
		{Network: "udp4", Addr: "127.0.0.1:8080"},
		{Network: "udp4", Addr: ":0"},
		{Network: "udp6", Addr: ":0"},
	}

	for _, factory := range tab {
		trans, err := factory.Open()
		if assert.NoError(err) && assert.NotNil(trans) {
			addrs := trans.LocalAddresses()
			assert.NotEmpty(addrs)

			t.Logf("factory=%v addrs=%v", factory, addrs)
			err = trans.Close()
			assert.NoError(err)
		}
	}
}

func Benchmark(b *testing.B) {
	A, err := Config{Network: "udp4"}.Open()
	if err != nil {
		b.Fatal(err)
	}
	defer A.Close()

	B, err := Config{Network: "udp4"}.Open()
	if err != nil {
		b.Fatal(err)
	}
	defer B.Close()

	var (
		msg = []byte("hello")
		dst = B.LocalAddresses()[0]
		out = make([]byte, 100)
	)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = A.WriteMessage(msg, dst)
		if err != nil {
			b.Fatal(err)
		}

		n, _, err := B.ReadMessage(out)
		if err != nil {
			b.Fatal(err)
		}

		if !bytes.Equal(out[:n], msg) {
			b.Fatalf("invalid message")
		}
	}
}

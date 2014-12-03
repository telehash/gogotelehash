package inproc

import (
	"bytes"
	"testing"
)

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

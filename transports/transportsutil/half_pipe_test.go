package transportsutil

import (
	"bytes"
	"testing"
)

func BenchmarkHalfPipe(b *testing.B) {
	var (
		p   = NewHalfPipe()
		in  = bytes.Repeat([]byte{'x'}, 1024)
		out = make([]byte, 1024)
	)

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p.PushMessage(in)
		p.Read(out)
	}
}

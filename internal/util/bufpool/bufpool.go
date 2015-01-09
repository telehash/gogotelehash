package bufpool

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

const bufferSize = 1500

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &Buffer{make([]byte, 0, bufferSize), true, 1}
	},
}

type Buffer struct {
	bytes    []byte
	fromPool bool
	flags    uint32
}

func New() *Buffer {
	b := bufferPool.Get().(*Buffer)

	if !atomic.CompareAndSwapUint32(&b.flags, 1, 0) {
		panic("insecure access to buffer")
	}

	return b
}

func (b *Buffer) secure() {
	if b == nil {
		return
	}

	if atomic.LoadUint32(&b.flags) == 1 {
		panic("insecure access to buffer")
	}
}

func (b *Buffer) Len() int {
	if b == nil {
		return 0
	}

	b.secure()
	return len(b.bytes)
}

func (b *Buffer) Get(buf []byte) []byte {
	b.secure()
	return append(buf, b.bytes...)
}

func (b *Buffer) Set(buf []byte) *Buffer {
	b.secure()
	if len(buf) > bufferSize {
		panic("data too large")
	}
	b.bytes = append(b.bytes[:0], buf...)
	return b
}

func (b *Buffer) RawBytes() []byte {
	b.secure()
	return b.bytes
}

func (b *Buffer) SetLen(n int) *Buffer {
	b.secure()
	b.bytes = b.bytes[:n]
	return b
}

func (b *Buffer) WriteTo(w io.Writer) (int, error) {
	b.secure()
	return w.Write(b.bytes)
}

func (b *Buffer) Free() {
	if b == nil {
		return
	}

	if !atomic.CompareAndSwapUint32(&b.flags, 0, 1) {
		panic("insecure access to buffer")
	}

	if !b.fromPool {
		return
	}

	if b.bytes == nil || cap(b.bytes) != bufferSize {
		panic("invalid buffer return")
	}

	b.bytes = b.bytes[:0]
	bufferPool.Put(b)
}

func (b *Buffer) String() string {
	return fmt.Sprintf("%q", b.bytes)
}

func (b *Buffer) GoString() string {
	return fmt.Sprintf("%q", b.bytes)
}

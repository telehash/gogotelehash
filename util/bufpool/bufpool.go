package bufpool

import (
	"sync"
)

const bufferSize = 1500

var bufferPool = sync.Pool{
	New: func() interface{} { return make([]byte, bufferSize) },
}

func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func PutBuffer(buf []byte) {
	if cap(buf) != bufferSize {
		panic("invalid buffer return")
	}

	buf = buf[:bufferSize]
	bufferPool.Put(buf)
}

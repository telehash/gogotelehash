package bufpool

import (
	"sync"
)

const bufferSize = 1500

var zeroBuffer = make([]byte, bufferSize)

var bufferPool = sync.Pool{
	New: func() interface{} { return make([]byte, bufferSize) },
}

func GetBuffer() []byte {
	buf := bufferPool.Get().([]byte)
	return buf[:bufferSize]
}

func PutBuffer(buf []byte) {
	if cap(buf) != bufferSize {
		panic("invalid buffer return")
	}

	buf = buf[:bufferSize]
	copy(buf, zeroBuffer)

	bufferPool.Put(buf)
}

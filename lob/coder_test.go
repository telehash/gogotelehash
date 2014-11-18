package lob

import (
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
	"testing"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	var tab = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{"hello": 5}},
		{json: Header{"hello": 5}, Body: []byte("world")},
	}

	for _, e := range tab {
		data, err := Encode(e)
		assert.NoError(err)
		assert.NotEmpty(data)

		e.raw = data

		o, err := Decode(data)
		assert.NoError(err)
		assert.NotNil(o)

		assert.Equal(e, o)
	}
}

func BenchmarkEncode(b *testing.B) {
	var tab = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{"hello": 5}},
		{json: Header{"hello": 5}, Body: []byte("world")},
	}
	var l = len(tab)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(tab[i%l])
	}
}

func BenchmarkDecode(b *testing.B) {
	var src = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{"hello": 5}},
		{json: Header{"hello": 5}, Body: []byte("world")},
	}
	var l = len(src)
	var tab = make([][]byte, l)

	for i, e := range src {
		tab[i], _ = Encode(e)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(tab[i%l])
	}
}

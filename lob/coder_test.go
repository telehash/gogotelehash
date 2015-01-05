package lob

import (
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"testing"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	var tab = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}, Body: []byte("world")},
		{json: Header{HasC: true, C: 123}},
		{json: Header{HasAck: true, Ack: 123}},
		{json: Header{HasSeq: true, Seq: 123}},
		{json: Header{HasType: true, Type: "foo"}},
		{json: Header{HasMiss: true, Miss: []uint32{123, 246}}},
	}

	for i, e := range tab {
		var o *Packet
		data, err := Encode(e)
		if assert.NoError(err) && assert.NotEmpty(data) {
			o, err = Decode(data)
			if assert.NoError(err) && assert.NotNil(o) {
				o.raw = nil
				assert.Equal(e, o)
			}
		}

		t.Logf("%d: %v => %v", i, e, o)

	}
}

func BenchmarkEncode(b *testing.B) {
	var tab = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}, Body: []byte("world")},
		{json: Header{HasC: true, C: 123}},
		{json: Header{HasAck: true, Ack: 123}},
		{json: Header{HasSeq: true, Seq: 123}},
		{json: Header{HasType: true, Type: "foo"}},
		{json: Header{HasMiss: true, Miss: []uint32{123, 246}}},
	}
	var l = len(tab)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e, _ := Encode(tab[i%l])
		bufpool.PutBuffer(e)
	}
}

func BenchmarkDecode(b *testing.B) {
	var src = []*Packet{
		{Head: []byte("h"), Body: []byte("world")},
		{Head: []byte("hello!")},
		{Head: []byte("hello!"), Body: []byte("world")},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}},
		{json: Header{Extra: map[string]interface{}{"hello": 5}}, Body: []byte("world")},
		{json: Header{HasC: true, C: 123}},
		{json: Header{HasAck: true, Ack: 123}},
		{json: Header{HasSeq: true, Seq: 123}},
		{json: Header{HasType: true, Type: "foo"}},
		{json: Header{HasMiss: true, Miss: []uint32{123, 246}}},
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

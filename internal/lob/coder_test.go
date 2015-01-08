package lob

import (
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"testing"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	var tab = []*Packet{
		New([]byte("world")).SetHeader(Header{Bytes: []byte("h")}),
		New(nil).SetHeader(Header{Bytes: []byte("hello!")}),
		New([]byte("world")).SetHeader(Header{Bytes: []byte("hello!")}),
		New(nil).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New([]byte("world")).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New(nil).SetHeader(Header{HasC: true, C: 123}),
		New(nil).SetHeader(Header{HasAck: true, Ack: 123}),
		New(nil).SetHeader(Header{HasSeq: true, Seq: 123}),
		New(nil).SetHeader(Header{HasType: true, Type: "foo"}),
		New(nil).SetHeader(Header{HasMiss: true, Miss: []uint32{123, 246}}),
	}

	for i, e := range tab {
		var o *Packet
		data, err := Encode(e)
		if assert.NoError(err) && assert.NotEmpty(data) {
			o, err = Decode(data)
			if assert.NoError(err) && assert.NotNil(o) {
				assert.Equal(e, o)
			}
		}

		t.Logf("%d: %v => %v", i, e, o)

		data.Free()
		o.Free()
	}
}

func BenchmarkEncode(b *testing.B) {
	var tab = []*Packet{
		New([]byte("world")).SetHeader(Header{Bytes: []byte("h")}),
		New(nil).SetHeader(Header{Bytes: []byte("hello!")}),
		New([]byte("world")).SetHeader(Header{Bytes: []byte("hello!")}),
		New(nil).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New([]byte("world")).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New(nil).SetHeader(Header{HasC: true, C: 123}),
		New(nil).SetHeader(Header{HasAck: true, Ack: 123}),
		New(nil).SetHeader(Header{HasSeq: true, Seq: 123}),
		New(nil).SetHeader(Header{HasType: true, Type: "foo"}),
		New(nil).SetHeader(Header{HasMiss: true, Miss: []uint32{123, 246}}),
	}
	var l = len(tab)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e, _ := Encode(tab[i%l])
		e.Free()
	}
}

func BenchmarkDecode(b *testing.B) {
	var src = []*Packet{
		New([]byte("world")).SetHeader(Header{Bytes: []byte("h")}),
		New(nil).SetHeader(Header{Bytes: []byte("hello!")}),
		New([]byte("world")).SetHeader(Header{Bytes: []byte("hello!")}),
		New(nil).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New([]byte("world")).SetHeader(Header{Extra: map[string]interface{}{"hello": 5}}),
		New(nil).SetHeader(Header{HasC: true, C: 123}),
		New(nil).SetHeader(Header{HasAck: true, Ack: 123}),
		New(nil).SetHeader(Header{HasSeq: true, Seq: 123}),
		New(nil).SetHeader(Header{HasType: true, Type: "foo"}),
		New(nil).SetHeader(Header{HasMiss: true, Miss: []uint32{123, 246}}),
	}
	var l = len(src)
	var tab = make([]*bufpool.Buffer, l)

	for i, e := range src {
		tab[i], _ = Encode(e)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, _ := Decode(tab[i%l])
		pkt.Free()
	}
}

package lob

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	var tab = []*Packet{
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

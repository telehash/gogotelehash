package cipherset

import (
	"encoding/hex"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	"github.com/telehash/gogotelehash/internal/util/base32util"
)

func TestHashnameCoding(t *testing.T) {
	var (
		assert = assert.New(t)
		k      Keys
	)

	k = Keys{
		0x3a: mustKey("hp6yglmmqwcbw5hno37uauh6fn6dx5oj7s5vtapaifrur2jv6zha"),
	}
	assert.Equal("nzf4f6j7ylv53z3m4egrwltv2t2yks4rtpaimeg3avwqsoshqxba",
		k.ToParts().ToHashname())

	k = Keys{
		0x3a: mustKey("hp6yglmmqwcbw5hno37uauh6fn6dx5oj7s5vtapaifrur2jv6zha"),
		0x1a: mustKey("vgjz3yjb6cevxjomdleilmzasbj6lcc7"),
	}
	assert.Equal("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa",
		k.ToParts().ToHashname())

	k = Keys{
		0x3a: mustHex("3bfd832d8c85841b74ed76ff4050fe2b7c3bf5c9fcbb5981e0416348e935f64e"),
	}
	p := k.ToParts()
	p[0x1a] = "ym7p66flpzyncnwkzxv2qk5dtosgnnstgfhw6xj2wvbvm7oz5oaq"
	assert.Equal("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa",
		p.ToHashname())
}

func mustHex(s string) []byte {
	d, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return d
}

func mustKey(s string) []byte {
	d, err := base32util.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return d
}

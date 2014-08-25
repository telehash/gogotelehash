package udp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocalAddresses(t *testing.T) {
	assert := assert.New(t)
	var tab = []*transport{
		{},
		{laddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}},
		{laddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}},
	}

	for _, trans := range tab {
		err := trans.Open()
		assert.NoError(err)

		addrs := trans.LocalAddresses()
		assert.NotEmpty(addrs)

		t.Logf("addrs=%+v", addrs)

		err = trans.Close()
		assert.NoError(err)
	}
}

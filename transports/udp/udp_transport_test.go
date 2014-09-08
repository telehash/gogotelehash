package udp

import (
	"testing"

	"bitbucket.org/simonmenke/go-telehash/util/events"
	"github.com/stretchr/testify/assert"
)

func TestLocalAddresses(t *testing.T) {
	assert := assert.New(t)
	var tab = []Config{
		{},
		{Network: "udp4", Addr: "127.0.0.1:0"},
		{Network: "udp4", Addr: "127.0.0.1:8080"},
		{Network: "udp4", Addr: ":0"},
		{Network: "udp6", Addr: ":0"},
	}

	var eventC = make(chan events.E)
	go events.Log(nil, eventC)

	for _, factory := range tab {
		trans, err := factory.Open(eventC)
		assert.NoError(err)

		addrs := trans.LocalAddresses()
		assert.NotEmpty(addrs)

		t.Logf("addrs=%+v", addrs)

		for _, addr := range addrs {
			assert.True(trans.CanHandleAddress(addr), "should be able to handle addr: %s", addr)
		}

		err = trans.Close()
		assert.NoError(err)
	}
}

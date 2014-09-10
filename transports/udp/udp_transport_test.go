package udp

import (
	"runtime"
	"testing"
	"time"

	"bitbucket.org/simonmenke/go-telehash/transports"
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

	{ // ensure we track the ticmer goroutine
		t := time.NewTicker(50 * time.Second)
		defer t.Stop()
	}

	var (
		numgo = runtime.NumGoroutine()
		e     = make(chan events.E)
		w     chan transports.WriteOp
		r     chan transports.ReadOp
		done  <-chan struct{}
	)
	go events.Log(nil, e)

	for _, factory := range tab {
		trans, err := factory.Open()
		assert.NoError(err)
		assert.NotNil(trans)

		w = make(chan transports.WriteOp)
		r = make(chan transports.ReadOp)
		done = trans.Run(w, r, e)

		close(w)
		<-done
	}

	close(e)
	runtime.Gosched()

	assert.Equal(numgo, runtime.NumGoroutine())
}

package scheduler

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScheduler(t *testing.T) {
	assert := assert.New(t)
	var (
		s   = New()
		now = time.Now()
		at  time.Time
		C   = 10000
	)

	s.Start()
	defer s.Stop()

	at = now.Add(10 * time.Second)
	s.NewEvent(noop).Schedule(at)

	go func() {
		for c := C - 1; c > 0; c-- {
			at = now.Add(5 * time.Second).Add(time.Duration(rand.Intn(3000)) * time.Millisecond)
			s.NewEvent(noop).Schedule(at)
		}
	}()

	c := 0
	for e := range s.C {
		assert.WithinDuration(e.At(), time.Now(), 2*time.Millisecond)
		c++

		if s.Idle() {
			break
		}
	}

	assert.Equal(C, c)
}

var noop = func() {}

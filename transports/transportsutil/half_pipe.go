package transportsutil

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/internal/util/bufpool"
)

type HalfPipe struct {
	mtx             sync.RWMutex
	cndRead         *sync.Cond
	deadlineReached bool
	deadlineTimer   *time.Timer
	closed          bool
	readQueue       [][]byte
}

func NewHalfPipe() *HalfPipe {
	conn := &HalfPipe{}
	conn.cndRead = sync.NewCond(&conn.mtx)
	return conn
}

func (c *HalfPipe) PushMessage(p []byte) {
	c.mtx.Lock()

	if c.closed {
		c.mtx.Unlock()
		return
	}

	buf := bufpool.GetBuffer()
	buf = buf[:len(p)]
	copy(buf, p)
	c.readQueue = append(c.readQueue, buf)

	c.cndRead.Signal()
	c.mtx.Unlock()
}

func (c *HalfPipe) Read(b []byte) (n int, err error) {
	c.mtx.Lock()

	for !c.closed && !c.deadlineReached && len(c.readQueue) == 0 {
		c.cndRead.Wait()
	}
	if c.closed {
		c.mtx.Unlock()
		return 0, io.EOF
	}
	if c.deadlineReached {
		c.mtx.Unlock()
		return 0, &net.OpError{Op: "read", Err: &timeoutError{}}
	}

	buf := c.readQueue[0]
	copy(b, buf)
	n = len(buf)
	bufpool.PutBuffer(buf)

	copy(c.readQueue, c.readQueue[1:])
	c.readQueue = c.readQueue[:len(c.readQueue)-1]

	if len(c.readQueue) > 0 {
		c.cndRead.Signal()
	}

	c.mtx.Unlock()
	return n, nil
}

func (c *HalfPipe) Close() error {
	c.mtx.Lock()
	c.closed = true
	c.cndRead.Signal()
	c.mtx.Unlock()
	return nil
}

func (c *HalfPipe) SetReadDeadline(t time.Time) error {
	c.mtx.Lock()

	now := time.Now()

	if c.deadlineTimer == nil {
		c.deadlineTimer = time.AfterFunc(time.Second, c.setDeadlineReached)
		c.deadlineTimer.Stop()
	}

	if t.IsZero() {
		c.deadlineTimer.Stop()
		c.deadlineReached = false
	} else if t.Before(now) {
		c.deadlineTimer.Stop()
		c.deadlineReached = true
	} else {
		c.deadlineTimer.Reset(t.Sub(now))
		c.deadlineReached = false
	}

	c.mtx.Unlock()
	return nil
}

func (c *HalfPipe) setDeadlineReached() {
	c.mtx.Lock()
	c.deadlineReached = true
	c.mtx.Unlock()
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

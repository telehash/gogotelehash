package e3x

import (
	"container/list"
	"io"
	"net"
	"sync"
)

var (
	_ net.Listener = (*Listener)(nil)
)

const defaultBacklogSize = 512

type Listener struct {
	mtx sync.Mutex
	cnd *sync.Cond

	endpoint    *Endpoint
	channelType string
	reliable    bool

	closed         bool
	maxBacklogSize int
	backlogSize    int
	queue          list.List
}

func newListener(endpoint *Endpoint, channelType string, reliable bool, maxBacklogSize int) *Listener {
	if maxBacklogSize <= 0 {
		maxBacklogSize = defaultBacklogSize
	}

	l := &Listener{endpoint: endpoint,
		channelType:    channelType,
		reliable:       reliable,
		maxBacklogSize: maxBacklogSize,
	}

	l.cnd = sync.NewCond(&l.mtx)

	return l
}

func (l *Listener) handle(c *Channel) {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.closed {
		// forget about channel
		ForgetterFromEndpoint(l.endpoint).ForgetChannel(c)
		return
	}

	if l.maxBacklogSize > 0 && l.backlogSize >= l.maxBacklogSize {
		// forget about channel
		ForgetterFromEndpoint(l.endpoint).ForgetChannel(c)
		return
	}

	if c.reliable != l.reliable || c.typ != l.channelType {
		// forget about channel
		ForgetterFromEndpoint(l.endpoint).ForgetChannel(c)
		return
	}

	l.queue.PushBack(c)
	l.backlogSize++
	l.cnd.Signal()
}

func (l *Listener) Addr() net.Addr {
	if l == nil {
		return nil
	}

	return l.endpoint.LocalHashname()
}

func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptChannel()
}

func (l *Listener) AcceptChannel() (*Channel, error) {
	if l == nil {
		return nil, io.EOF
	}

	l.mtx.Lock()
	defer l.mtx.Unlock()

WAIT:
	for !l.closed && l.backlogSize == 0 {
		l.cnd.Wait()
	}

	if l.closed {
		return nil, io.EOF
	}

	elem := l.queue.Front()
	if elem == nil {
		goto WAIT
	}

	// remove from queue
	l.queue.Remove(elem)
	l.backlogSize--

	// ignore nil values
	if elem.Value == nil {
		goto WAIT
	}

	c := elem.Value.(*Channel)

	if l.backlogSize > 0 {
		l.cnd.Signal()
	}

	return c, nil
}

func (l *Listener) Close() error {
	if l == nil {
		return nil
	}

	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.closed {
		return nil
	}

	if l.endpoint != nil {
		l.endpoint.unregisterListener(l.channelType)
	}

	forgetter := ForgetterFromEndpoint(l.endpoint)
	for e := l.queue.Front(); e != nil; e = e.Next() {
		c := e.Value.(*Channel)
		forgetter.ForgetChannel(c)
	}

	l.closed = true
	l.cnd.Broadcast()
	return nil
}

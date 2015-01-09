package e3x

import (
	"container/list"
	"errors"
	"io"
	"net"
	"sync"
)

var (
	_ net.Listener = (*Listener)(nil)
)

const defaultBacklogSize = 512

type listenerSet struct {
	dropChannelFunc func(c *Channel, reason error)
	addrFunc        func() net.Addr

	mtx       sync.RWMutex
	parent    *listenerSet
	listeners map[string]*Listener
}

var (
	ErrListenerClosed          = errors.New("listener closed")
	ErrListenerBacklogTooLarge = errors.New("listener backlog too large")
	ErrListenerInvalidType     = errors.New("listener inavlid channel type")
)

func newListenerSet() *listenerSet {
	return &listenerSet{}
}

func (set *listenerSet) Addr() net.Addr {
	if set == nil {
		return nil
	}

	if set.addrFunc != nil {
		return set.addrFunc()
	}

	return set.parent.Addr()
}

func (set *listenerSet) Inherit() *listenerSet {
	return &listenerSet{parent: set}
}

func (set *listenerSet) Get(typ string) *Listener {
	var (
		l *Listener
	)

	if set == nil {
		return nil
	}

	set.mtx.RLock()
	if set.listeners != nil {
		l = set.listeners[typ]
	}
	set.mtx.RUnlock()

	if l == nil {
		l = set.parent.Get(typ)
	}

	return l
}

func (set *listenerSet) remove(typ string) {
	set.mtx.Lock()
	defer set.mtx.Unlock()

	if set.listeners != nil {
		delete(set.listeners, typ)
	}
}

func (set *listenerSet) dropChannel(c *Channel, reason error) {
	if set.dropChannelFunc != nil {
		set.dropChannelFunc(c, reason)
		return
	}

	if set.parent != nil {
		set.parent.dropChannel(c, reason)
		return
	}
}

func (set *listenerSet) Listen(typ string, reliable bool) *Listener {
	set.mtx.Lock()
	defer set.mtx.Unlock()

	if set.listeners == nil {
		set.listeners = make(map[string]*Listener)
	}

	if _, f := set.listeners[typ]; f {
		panic("listener is already registered: " + typ)
	}

	l := newListener(set, typ, reliable, 0)
	set.listeners[typ] = l
	return l
}

type Listener struct {
	mtx sync.Mutex
	cnd *sync.Cond

	set         *listenerSet
	channelType string
	reliable    bool

	closed         bool
	maxBacklogSize int
	backlogSize    int
	queue          list.List
}

func newListener(set *listenerSet, channelType string, reliable bool, maxBacklogSize int) *Listener {
	if maxBacklogSize <= 0 {
		maxBacklogSize = defaultBacklogSize
	}

	l := &Listener{
		set:            set,
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
		l.set.dropChannel(c, ErrListenerClosed)
		return
	}

	if l.maxBacklogSize > 0 && l.backlogSize >= l.maxBacklogSize {
		// forget about channel
		l.set.dropChannel(c, ErrListenerBacklogTooLarge)
		return
	}

	if c.reliable != l.reliable || c.typ != l.channelType {
		// forget about channel
		l.set.dropChannel(c, ErrListenerInvalidType)
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

	return l.set.Addr()
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

	if l.set != nil {
		l.set.remove(l.channelType)
	}

	for e := l.queue.Front(); e != nil; e = e.Next() {
		c := e.Value.(*Channel)
		l.set.dropChannel(c, ErrListenerClosed)
	}

	l.closed = true
	l.cnd.Broadcast()
	return nil
}

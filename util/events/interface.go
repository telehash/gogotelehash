package events

import (
	"log"
	"sync"
)

type E interface {
	String() string
}

type Hub struct {
	mtx sync.RWMutex
	l   []chan<- E
}

func Emit(out chan<- E, in E) (ok bool) {
	if out == nil || in == nil {
		return false
	}

	defer func() {
		ok = recover() == nil
	}()

	out <- in
	return true
}

func FanOut(out []chan<- E, in E) {
	for _, c := range out {
		Emit(c, in)
	}
}

func Log(out *log.Logger, in <-chan E) {
	for e := range in {
		if out == nil {
			log.Printf("event: %s", e)
		} else {
			out.Printf("event: %s", e)
		}
	}
}

func (h *Hub) Emit(in E) {
	h.mtx.RLock()
	FanOut(h.l, in)
	h.mtx.RUnlock()
}

func (e *Hub) Subscribe(c chan<- E) {
	e.mtx.Lock()
	e.l = append(e.l, c)
	e.mtx.Unlock()
}

func (e *Hub) Unubscribe(c chan<- E) {
	e.mtx.Lock()
	l := len(e.l)
	for i, d := range e.l {
		if d == c {
			if l-1 > i {
				copy(e.l[i:], e.l[i+1:])
			}
			e.l = e.l[:l-1]
			break
		}
	}
	e.mtx.Unlock()
}

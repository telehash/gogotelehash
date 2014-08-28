package scheduler

import (
	"container/heap"
	"sync"
	"time"
)

type Scheduler struct {
	C         <-chan *Event
	c         chan *Event
	mtx       sync.Mutex
	items     schedulerHeap
	running   bool
	cSchedule chan opSchedule
	cStop     chan struct{}
	cIdle     chan bool
	cNext     chan time.Time
}

type schedulerHeap []*Event

type Event struct {
	s       *Scheduler
	at      time.Time
	pending bool
	f       func()

	_idx int
	_at  time.Time
}

type opSchedule struct {
	prevAt time.Time
	nextAt time.Time
	e      *Event
}

func New() *Scheduler {
	c := make(chan *Event)
	return &Scheduler{
		C:         c,
		c:         c,
		cStop:     make(chan struct{}),
		cSchedule: make(chan opSchedule),
		cIdle:     make(chan bool),
		cNext:     make(chan time.Time),
	}
}

func (s *Scheduler) Start() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.running {
		return
	}

	s.running = true
	go s.run()
}

func (s *Scheduler) Stop() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if !s.running {
		return
	}

	s.cStop <- struct{}{}
	s.running = false
}

func (s *Scheduler) Idle() bool {
	return <-s.cIdle
}

func (s *Scheduler) Next() time.Time {
	return <-s.cNext
}

func (s *Scheduler) NewEvent(f func()) *Event {
	return &Event{s: s, f: f}
}

func (e *Event) Exec() {
	if !e.pending {
		return
	}
	e.pending = false
	e.at = time.Time{}

	e.f()
}

func (e *Event) ScheduleAfter(d time.Duration) {
	e.Schedule(time.Now().Add(d))
}

func (e *Event) Schedule(at time.Time) {
	prevAt := e.at
	nextAt := at
	e.pending = true
	e.at = nextAt

	e.s.cSchedule <- opSchedule{prevAt, nextAt, e}
}

func (e *Event) Cancel() {
	prevAt := e.at
	nextAt := time.Time{}
	e.pending = false
	e.at = nextAt

	e.s.cSchedule <- opSchedule{prevAt, nextAt, e}
}

func (e *Event) At() time.Time {
	return e.at
}

func (s *Scheduler) run() {
	var (
		timer   = time.NewTimer(time.Minute)
		current *Event
	)

	defer timer.Stop()

	// timer starts in the stopped state
	timer.Stop()

	for {

		// select mode
		var (
			c           = s.c
			timerC      = timer.C
			idle        = len(s.items) == 0
			nextAt      time.Time
			adjustTimer bool
		)

		if current == nil {
			c = nil
		} else {
			timerC = nil
		}

		if !idle {
			nextAt = s.items[0].at
		}

		select {

		case s.cIdle <- idle:

		case s.cNext <- nextAt:

		case <-s.cStop:
			return

		case op := <-s.cSchedule:
			if op.prevAt.IsZero() {
				if op.nextAt.IsZero() {
					// ignore

				} else {
					// push
					op.e._at = op.nextAt
					heap.Push(&s.items, op.e)
					if op.e._idx == 0 {
						adjustTimer = true
					}

				}
			} else {
				if op.nextAt.IsZero() {
					// remove
					if op.e._idx >= 0 {
						if op.e._idx == 0 {
							adjustTimer = true
						}
						heap.Remove(&s.items, op.e._idx)
					}

				} else {
					// update (or reschedule)
					if op.e._idx >= 0 {
						if op.e._idx == 0 {
							adjustTimer = true
						}
						s.items[op.e._idx]._at = op.nextAt
						heap.Fix(&s.items, op.e._idx)
						if op.e._idx == 0 {
							adjustTimer = true
						}
					} else {
						op.e._at = op.nextAt
						heap.Push(&s.items, op.e)
						if op.e._idx == 0 {
							adjustTimer = true
						}
					}

				}
			}
			s.adjustTimer(timer)

		case c <- current:
			current = nil

		case <-timerC:
			current = heap.Pop(&s.items).(*Event)
			adjustTimer = true

		}

		if adjustTimer {
			s.adjustTimer(timer)
		}
	}
}

func (s *Scheduler) adjustTimer(timer *time.Timer) {
	if len(s.items) == 0 {
		timer.Stop()
		return
	}

	timer.Reset(s.items[0]._at.Sub(time.Now()))
}

func (s schedulerHeap) Len() int {
	return len(s)
}

func (s schedulerHeap) Less(i, j int) bool {
	return s[i]._at.Before(s[j]._at)
}

func (s schedulerHeap) Swap(i, j int) {
	ei, ej := s[i], s[j]
	ei._idx = j
	ej._idx = i
	s[i], s[j] = ej, ei
}

func (s *schedulerHeap) Push(x interface{}) {
	old := *s
	y := x.(*Event)
	y._idx = len(old)
	*s = append(old, y)
}

func (s *schedulerHeap) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	x._idx = -1
	return x
}

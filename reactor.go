package telehash

import (
	"errors"
	"github.com/rcrowley/go-metrics"
	"sync"
	"time"
)

var (
	errReactorClosed = errors.New("reactor: is closed")
)

type reactor_t struct {
	wg               sync.WaitGroup
	sw               *Switch
	defered          bool
	current_cmd      *cmd
	shutdown         chan bool
	enqueue_commands chan *cmd
	run_commands     chan *cmd
	met_queue_depth  metrics.Counter
}

type cmd struct {
	execer  execer
	reply   chan error
	created time.Time
}

type execer interface {
	Exec(sw *Switch) error
}

type backlog_t []*cmd

func (b *backlog_t) RescheduleAll(r *reactor_t) {
	l := *b
	if len(l) > 0 {
		*b = nil
		for _, cmd := range l {
			err := r.push(cmd)
			if err != nil {
				cmd.cancel(err)
			}
		}
	}
}

func (b *backlog_t) RescheduleOne(r *reactor_t) {
	l := *b
	if len(l) > 0 {
		// get first command
		cmd := l[0]

		// remove from backlog
		copy(l, l[1:])
		l = l[:len(l)-1]
		*b = l

		err := r.push(cmd)
		if err != nil {
			cmd.cancel(err)
		}
	}
}

func (b *backlog_t) CancelAll(err error) {
	l := *b
	*b = nil

	for _, cmd := range l {
		cmd.cancel(err)
	}
}

func (c *cmd) cancel(err error) {
	defer func() { recover() }()
	if c.reply != nil {
		c.reply <- err
		close(c.reply)
	}
}

func (r *reactor_t) Run() {
	r.enqueue_commands = make(chan *cmd)
	r.run_commands = make(chan *cmd)
	r.shutdown = make(chan bool)
	r.met_queue_depth = metrics.NewRegisteredCounter("reactor.queue.depth", r.sw.met)

	r.wg.Add(1)
	go r.run_controller()

	r.wg.Add(1)
	go r.run_worker()
}

func (r *reactor_t) run_controller() {
	defer r.wg.Done()

	var (
		backlog      []*cmd
		run_commands chan *cmd
		next_cmd     *cmd
	)

	for {
		if len(backlog) > 0 {
			run_commands = r.run_commands
			next_cmd = backlog[0]
		} else {
			run_commands = nil
		}

		select {

		case <-r.shutdown:
			close(r.enqueue_commands)
			close(r.run_commands)
			close(r.shutdown)

			for _, cmd := range backlog {
				cmd.cancel(errReactorClosed)
			}

			return

		case cmd := <-r.enqueue_commands:
			backlog = append(backlog, cmd)

		case run_commands <- next_cmd:
			copy(backlog, backlog[1:])
			backlog = backlog[:len(backlog)-1]

		}
	}
}

func (r *reactor_t) run_worker() {
	defer r.wg.Done()

	var (
		exec_timer     = metrics.NewRegisteredTimer("reactor.exec.duration", r.sw.met)
		latencey_timer = metrics.NewRegisteredTimer("reactor.exec.latency", r.sw.met)
		defer_counter  = metrics.NewRegisteredCounter("reactor.defer.count", r.sw.met)
	)

	for cmd := range r.run_commands {
		exec_timer.Time(func() {
			r.exec(cmd)
		})
		if !r.defered {
			r.met_queue_depth.Dec(1)
			latencey_timer.UpdateSince(cmd.created)
		} else {
			defer_counter.Inc(1)
		}
	}
}

func (r *reactor_t) Stop() (err error) {
	defer func(err_ptr *error) {
		if r := recover(); r != nil {
			*err_ptr = errReactorClosed
		}
	}(&err)

	r.shutdown <- true
	return
}

func (r *reactor_t) Wait() {
	r.wg.Wait()
}

func (r *reactor_t) StopAndWait() {
	r.Stop()
	r.Wait()
}

func (r *reactor_t) exec(c *cmd) {
	var (
		err error
	)

	defer func() {
		if c.reply != nil && !r.defered {
			c.cancel(err)
		}
	}()

	r.current_cmd = c
	r.defered = false
	err = c.execer.Exec(r.sw)
}

func (r *reactor_t) Defer(b *backlog_t) {
	r.defered = true
	*b = append(*b, r.current_cmd)
}

func (r *reactor_t) Call(e execer) error {
	return <-r.CallAsync(e)
}

func (r *reactor_t) CallAsync(e execer) <-chan error {
	c := cmd{e, make(chan error, 1), time.Now()}

	err := r.push(&c)
	if err != nil {
		c.cancel(err)
	} else {
		r.met_queue_depth.Inc(1)
	}

	return c.reply
}

func (r *reactor_t) Cast(e execer) {
	err := r.push(&cmd{e, nil, time.Now()})
	if err == nil {
		r.met_queue_depth.Inc(1)
	}
}

func (r *reactor_t) push(c *cmd) (err error) {
	defer func(err_ptr *error) {
		if r := recover(); r != nil {
			*err_ptr = errReactorClosed
		}
	}(&err)

	r.enqueue_commands <- c
	return
}

func (r *reactor_t) CastAfter(d time.Duration, e execer) *time.Timer {
	return time.AfterFunc(d, func() { r.Cast(e) })
}

func (r *reactor_t) CastAt(t time.Time, e execer) *time.Timer {
	return r.CastAfter(t.Sub(time.Now()), e)
}

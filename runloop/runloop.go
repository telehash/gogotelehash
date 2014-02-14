package runloop

import (
	"errors"
	"github.com/rcrowley/go-metrics"
	"sync"
	"time"
)

var (
	errReactorClosed = errors.New("reactor: is closed")
)

type RunLoop struct {
	State   interface{}
	Metrics metrics.Registry

	wg               sync.WaitGroup
	defered          bool
	current_cmd      *privateCommand
	shutdown         chan bool
	enqueue_commands chan *privateCommand
	run_commands     chan *privateCommand

	met_queue_depth metrics.Counter
}

type privateCommand struct {
	command Command
	reply   chan error
	created time.Time
}

type Command interface {
	Exec(state interface{}) error
}

func (c *privateCommand) cancel(err error) {
	defer func() { recover() }()
	if c.reply != nil {
		c.reply <- err
		close(c.reply)
	}
}

func (l *RunLoop) Run() {
	if l.Metrics == nil {
		l.Metrics = metrics.NewRegistry()
	}

	l.enqueue_commands = make(chan *privateCommand)
	l.run_commands = make(chan *privateCommand)
	l.shutdown = make(chan bool)
	l.met_queue_depth = metrics.NewRegisteredCounter("reactor.queue.depth", l.Metrics)

	l.wg.Add(1)
	go l.run_controller()

	l.wg.Add(1)
	go l.run_worker()
}

func (l *RunLoop) run_controller() {
	defer l.wg.Done()

	var (
		backlog      []*privateCommand
		run_commands chan *privateCommand
		next_cmd     *privateCommand
	)

	for {
		if len(backlog) > 0 {
			run_commands = l.run_commands
			next_cmd = backlog[0]
		} else {
			run_commands = nil
		}

		select {

		case <-l.shutdown:
			close(l.enqueue_commands)
			close(l.run_commands)
			close(l.shutdown)

			for _, cmd := range backlog {
				cmd.cancel(errReactorClosed)
			}

			return

		case cmd := <-l.enqueue_commands:
			backlog = append(backlog, cmd)

		case run_commands <- next_cmd:
			copy(backlog, backlog[1:])
			backlog = backlog[:len(backlog)-1]

		}
	}
}

func (l *RunLoop) run_worker() {
	defer l.wg.Done()

	var (
		exec_timer     = metrics.NewRegisteredTimer("reactor.exec.duration", l.Metrics)
		latencey_timer = metrics.NewRegisteredTimer("reactor.exec.latency", l.Metrics)
		defer_counter  = metrics.NewRegisteredCounter("reactor.defer.count", l.Metrics)
	)

	for cmd := range l.run_commands {
		exec_timer.Time(func() {
			l.exec(cmd)
		})

		if !l.defered {
			l.met_queue_depth.Dec(1)
			latencey_timer.UpdateSince(cmd.created)
		} else {
			defer_counter.Inc(1)
		}
	}
}

func (l *RunLoop) Stop() (err error) {
	defer func(err_ptr *error) {
		if r := recover(); r != nil {
			*err_ptr = errReactorClosed
		}
	}(&err)

	l.shutdown <- true
	return
}

func (l *RunLoop) Wait() {
	l.wg.Wait()
}

func (l *RunLoop) StopAndWait() {
	l.Stop()
	l.Wait()
}

func (l *RunLoop) exec(c *privateCommand) {
	var (
		err error
	)

	defer func() {
		if c.reply != nil && !l.defered {
			c.cancel(err)
		}
	}()

	l.current_cmd = c
	l.defered = false
	err = c.command.Exec(l.State)
}

func (l *RunLoop) Call(e Command) error {
	return <-l.CallAsync(e)
}

func (l *RunLoop) CallAsync(e Command) <-chan error {
	c := privateCommand{e, make(chan error, 1), time.Now()}

	err := l.push(&c)
	if err != nil {
		c.cancel(err)
	} else {
		l.met_queue_depth.Inc(1)
	}

	return c.reply
}

func (l *RunLoop) Cast(e Command) {
	err := l.push(&privateCommand{e, nil, time.Now()})
	if err == nil {
		l.met_queue_depth.Inc(1)
	}
}

func (l *RunLoop) push(c *privateCommand) (err error) {
	defer func(err_ptr *error) {
		if r := recover(); r != nil {
			*err_ptr = errReactorClosed
		}
	}(&err)

	l.enqueue_commands <- c
	return
}

func (l *RunLoop) CastAfter(d time.Duration, e Command) *time.Timer {
	return time.AfterFunc(d, func() { l.Cast(e) })
}

func (l *RunLoop) CastAt(t time.Time, e Command) *time.Timer {
	return l.CastAfter(t.Sub(time.Now()), e)
}

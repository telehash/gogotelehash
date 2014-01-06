package telehash

import (
	"sync"
	"time"
)

type reactor_t struct {
	wg          sync.WaitGroup
	sw          *Switch
	defered     bool
	current_cmd cmd
	commands    chan cmd
}

type cmd struct {
	execer execer
	reply  chan bool
}

type execer interface {
	Exec(sw *Switch)
}

type backlog_t []cmd

func (b *backlog_t) RescheduleAll(r *reactor_t) {
	l := *b
	*b = nil

	go func() {
		for _, cmd := range l {
			r.commands <- cmd
		}
	}()
}

func (b *backlog_t) RescheduleOne(r *reactor_t) {
	l := *b

	if len(l) == 0 {
		return
	}

	cmd := l[0]
	copy(l, l[1:])
	l = l[:len(l)-1]
	*b = l

	go func() {
		r.commands <- cmd
	}()
}

func (r *reactor_t) Run() {
	r.commands = make(chan cmd)
	r.wg.Add(1)
	go r.run()
}

func (r *reactor_t) run() {
	defer r.wg.Done()

	for cmd := range r.commands {
		r.exec(cmd)
	}
}

func (r *reactor_t) Stop() {
	close(r.commands)
}

func (r *reactor_t) Wait() {
	r.wg.Wait()
}

func (r *reactor_t) StopAndWait() {
	r.Stop()
	r.Wait()
}

func (r *reactor_t) exec(c cmd) {
	defer func() {
		if c.reply != nil && !r.defered {
			c.reply <- true
		}
	}()

	r.current_cmd = c
	r.defered = false
	c.execer.Exec(r.sw)
}

func (r *reactor_t) Defer(b *backlog_t) {
	r.defered = true
	*b = append(*b, r.current_cmd)
}

func (r *reactor_t) Call(e execer) {
	c := cmd{e, make(chan bool)}
	r.commands <- c
	<-c.reply
}

func (r *reactor_t) CallAsync(e execer) <-chan bool {
	c := cmd{e, make(chan bool, 1)}
	r.commands <- c
	return c.reply
}

func (r *reactor_t) Cast(e execer) {
	r.commands <- cmd{e, nil}
}

func (r *reactor_t) CastAfter(d time.Duration, e execer) *time.Timer {
	return time.AfterFunc(d, func() { r.Cast(e) })
}

func (r *reactor_t) CastAt(t time.Time, e execer) *time.Timer {
	return r.CastAfter(t.Sub(time.Now()), e)
}

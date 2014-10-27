package main

import (
	"math/rand"
	"time"

	"github.com/telehash/gogotelehash/e3x"
)

type Reporter interface {
	Next()
	Submit()

	Error(err error)
	Panic(p interface{})
}

type Test interface {
	Name() string
	Setup(e *e3x.Endpoint)
	Run(e *e3x.Endpoint, r Reporter)
}

type PeriodicTest interface {
	Test
	Frequency() (min, max time.Duration)
}

type periodicTest struct {
	PeriodicTest
}

func (p *periodicTest) Run(e *e3x.Endpoint, r Reporter) {
	min, max := p.PeriodicTest.Frequency()
	for {
		wait := min + time.Duration(rand.Uint32(uint32(max)-uint32(min)))
		time.Sleep(wait)

		func() {
			r.Next()
			defer r.Submit()

			defer func() {
				if v := recover(); v != nil {
					r.Panic(v)
				}
			}()

			p.PeriodicTest.Run(e, r)
		}()
	}
}

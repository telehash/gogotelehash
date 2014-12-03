package main

import (
	"time"
)

func init() {
	RegisterTest("sanity").
		SUT(Sanity_SUT).
		Driver(Sanity_Driver)
}

func Sanity_SUT(ctx *Context) error {
	ctx.Ready()
	time.Sleep(10 * time.Second)
	return nil
}

func Sanity_Driver(ctx *Context) error {
	ctx.Ready()
	time.Sleep(5 * time.Second)
	ctx.Done()
	return nil
}

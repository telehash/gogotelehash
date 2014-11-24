package main

import (
	"log"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/modules/mesh"
)

func init() {
	RegisterTest("net-link").
		SUT(NetLink_SUT).
		Driver(NetLink_Driver)
}

func NetLink_SUT(ctx *Context) error {
	e, err := e3x.Open(
		e3x.Log(ctx.Out),
		mesh.Module(nil))
	if err != nil {
		return err
	}

	ctx.WriteIdenity(e)
	ctx.Ready()

	ctx.AwaitDone()

	err = e.Stop()
	if err != nil {
		return err
	}

	log.Println("Bye")
	return nil
}

func NetLink_Driver(ctx *Context) error {
	e, err := e3x.Open(
		e3x.Log(ctx.Out),
		mesh.Module(nil))
	if err != nil {
		return err
	}

	{
		var ident = ctx.ReadIdenity("sut")
		ctx.Ready()

		m := mesh.FromEndpoint(e)
		tag, err := m.Link(ident, nil)
		if err != nil {
			return err
		}

		time.Sleep(150 * time.Second)

		tag.Release()
	}

	ctx.Done()

	err = e.Stop()
	if err != nil {
		return err
	}

	log.Println("Bye")
	return nil
}

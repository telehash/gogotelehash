package main

import (
	"log"
	"time"

	"github.com/telehash/gogotelehash"
)

func init() {
	RegisterTest("net-link").
		Worker(NetLink_Worker).
		Driver(NetLink_Driver)
}

func NetLink_Worker(ctx *Context) error {
	e, err := telehash.Open()
	if err != nil {
		return err
	}

	ctx.WriteIdentity(e)
	ctx.Ready()

	time.Sleep(5 * time.Minute)

	err = e.Close()
	if err != nil {
		return err
	}

	log.Println("Bye")
	return nil
}

func NetLink_Driver(ctx *Context) error {
	e, err := telehash.Open()
	if err != nil {
		return err
	}

	{
		var ident = ctx.ReadIdentity("worker")
		ctx.Ready()

		_, err := e.Dial(ident)
		if err != nil {
			return err
		}

		time.Sleep(150 * time.Second)
	}

	ctx.Done()
	err = e.Close()
	if err != nil {
		return err
	}

	log.Println("Bye")
	return nil
}

package main

import (
	"io"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/lob"
)

func init() {
	RegisterTest("channel-reliable").
		SUT(ChannelReliable_SUT).
		Driver(ChannelReliable_Driver)
}

func ChannelReliable_SUT(ctx *Context) error {
	e, err := e3x.Open(
		e3x.Log(ctx.Out))
	if err != nil {
		return err
	}

	ctx.WriteIdenity(e)
	ctx.Ready()

	l := e.Listen("test-channel", true)
	c, err := l.AcceptChannel()
	if err != nil {
		return err
	}

	for i := 1; true; i++ {
		pkt, err := c.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if i == 1 {
			c.WritePacket(&lob.Packet{})
		}

		token, _ := pkt.Header().GetString("token")
		ctx.Assert(i, token)
	}

	err = c.Close()
	if err != nil {
		return err
	}

	err = e.Close()
	if err != nil {
		return err
	}

	return nil
}

func ChannelReliable_Driver(ctx *Context) error {
	e, err := e3x.Open(
		e3x.Log(ctx.Out))
	if err != nil {
		return err
	}
	ctx.Ready()

	var (
		ident = ctx.ReadIdenity("sut")
		pkt   *lob.Packet
		token string
	)

	c, err := e.Open(ident, "test-channel", true)
	if err != nil {
		return err
	}

	token = RandomString(10)
	ctx.Assert(1, token)
	pkt = &lob.Packet{}
	pkt.Header().SetString("token", token)
	err = c.WritePacket(pkt)
	if err != nil {
		return err
	}

	c.ReadPacket()

	token = RandomString(10)
	ctx.Assert(2, token)
	pkt = &lob.Packet{}
	pkt.Header().SetString("token", token)
	err = c.WritePacket(pkt)
	if err != nil {
		return err
	}

	token = RandomString(10)
	ctx.Assert(3, token)
	pkt = &lob.Packet{}
	pkt.Header().SetString("token", token)
	err = c.WritePacket(pkt)
	if err != nil {
		return err
	}

	err = c.Close()
	if err != nil {
		return err
	}

	ctx.Done()
	err = e.Close()
	if err != nil {
		return err
	}

	return nil
}

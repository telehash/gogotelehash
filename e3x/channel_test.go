package e3x

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports/mux"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

type channelTestSuite struct {
	suite.Suite
	A      *Endpoint
	B      *Endpoint
	events chan events.E
}

func TestChannels(t *testing.T) {
	suite.Run(t, &channelTestSuite{})
}

func (c *channelTestSuite) SetupTest() {
	return

	var (
		assert = c.Assertions
		err    error
		tc     = mux.Config{
			udp.Config{Network: "udp4"},
			udp.Config{Network: "udp6"},
		}
	)

	c.events = make(chan events.E)
	go events.Log(nil, c.events)

	ka, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	kb, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	c.A = New(cipherset.Keys{0x3a: ka}, tc)
	c.B = New(cipherset.Keys{0x3a: kb}, tc)

	c.A.Subscribe(c.events)
	c.B.Subscribe(c.events)

	err = c.A.Start()
	assert.NoError(err)

	err = c.B.Start()
	assert.NoError(err)

	time.Sleep(1 * time.Second)
}

func (c *channelTestSuite) TearDownTest() {
	return

	var (
		assert = c.Assertions
		err    error
	)

	err = c.A.Stop()
	assert.NoError(err)

	err = c.B.Stop()
	assert.NoError(err)

	close(c.events)
}

func (s *channelTestSuite) TestBasicUnrealiable() {
	var (
		assert = s.Assertions
		c      *Channel
		w      = make(chan opExchangeWrite, 1)
		r      = make(chan opExchangeRead, 1)
		pkt    *lob.Packet
		err    error
	)

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", false, false,
		w, r)
	go c.run()

	go func() {
		op := <-w

		assert.NotNil(op.pkt)
		if op.pkt != nil {
			assert.Equal("ping", string(op.pkt.Body))
		}

		op.cErr <- nil
	}()
	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	r <- opExchangeRead{&lob.Packet{Body: []byte("pong")}, nil}

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}

	go func() {
		op := <-w

		assert.NotNil(op.pkt)
		if op.pkt != nil {
			end, _ := op.pkt.Header().GetBool("end")
			assert.True(end)
		}

		op.cErr <- nil
	}()
	err = c.Close()
	assert.NoError(err)
}

func (s *channelTestSuite) TestBasicRealiable() {
	var (
		assert = s.Assertions
		c      *Channel
		w      = make(chan opExchangeWrite, 1)
		r      = make(chan opExchangeRead, 1)
		pkt    *lob.Packet
		err    error
	)

	c = newChannel(
		hashname.H("a-hashname"),
		"ping", true, false,
		w, r)
	go c.run()

	go func() {
		op := <-w

		assert.NotNil(op.pkt)
		if op.pkt != nil {
			seq, _ := op.pkt.Header().GetInt("seq")
			assert.Equal(1, seq)
			assert.Equal("ping", string(op.pkt.Body))
		}

		op.cErr <- nil
	}()
	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt = &lob.Packet{Body: []byte("pong")}
	pkt.Header().SetUint32("seq", 1)
	r <- opExchangeRead{pkt, nil}

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}

	go func() {
		op := <-w

		assert.NotNil(op.pkt)
		if op.pkt != nil {
			seq, _ := op.pkt.Header().GetInt("seq")
			end, _ := op.pkt.Header().GetBool("end")
			assert.Equal(2, seq)
			assert.True(end)
		}

		op.cErr <- nil
	}()
	err = c.Close()
	assert.NoError(err)
}

func (s *channelTestSuite) TestPingPong() {
	return // SKIP

	var (
		assert = s.Assertions
		A      = s.A
		B      = s.B
		c      *Channel
		addr   *Addr
		pkt    *lob.Packet
		err    error
	)

	A.AddHandler("ping", HandlerFunc(func(c *Channel) {
		var (
			err error
		)

		defer c.Close()

		pkt, err = c.ReadPacket()
		assert.NoError(err)
		assert.NotNil(pkt)
		assert.Equal("ping", string(pkt.Body))

		err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
		assert.NoError(err)
	}))

	addr, err = A.LocalAddr()
	s.T().Logf("A.LocalAddr => %v", addr.addrs)
	assert.NoError(err)

	c, err = B.Dial(addr, "ping", false)
	assert.NoError(err)
	assert.NotNil(c)

	defer c.Close()

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}
}

func (s *channelTestSuite) TestPingPongReliable() {
	return // SKIP

	var (
		assert = s.Assertions
		A      = s.A
		B      = s.B
		c      *Channel
		addr   *Addr
		pkt    *lob.Packet
		err    error
	)

	A.AddHandler("ping", HandlerFunc(func(c *Channel) {
		var (
			err error
		)

		defer c.Close()

		pkt, err = c.ReadPacket()
		assert.NoError(err)
		assert.NotNil(pkt)
		assert.Equal("ping", string(pkt.Body))

		err = c.WritePacket(&lob.Packet{Body: []byte("pong")})
		assert.NoError(err)
	}))

	addr, err = A.LocalAddr()
	assert.NoError(err)

	c, err = B.Dial(addr, "ping", true)
	assert.NoError(err)
	assert.NotNil(c)

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	if pkt != nil {
		assert.Equal("pong", string(pkt.Body))
	}

	err = c.Close()
	assert.NoError(err)
}

func (s *channelTestSuite) TestFloodReliable() {
	return // SKIP

	var (
		assert = s.Assertions
		A      = s.A
		B      = s.B
		c      *Channel
		addr   *Addr
		pkt    *lob.Packet
		err    error
	)

	A.AddHandler("flood", HandlerFunc(func(c *Channel) {
		var (
			err error
		)

		defer c.Close()

		pkt, err = c.ReadPacket()
		assert.NoError(err)
		assert.NotNil(pkt)

		for i := 0; i < 1000000; i++ {
			pkt := &lob.Packet{}
			pkt.Header().SetInt("flood_id", i)
			err = c.WritePacket(pkt)
			assert.NoError(err)
		}
	}))

	addr, err = A.LocalAddr()
	assert.NoError(err)

	c, err = B.Dial(addr, "flood", true)
	assert.NoError(err)
	assert.NotNil(c)

	defer c.Close()

	err = c.WritePacket(&lob.Packet{})
	assert.NoError(err)

	lastId := -1
	for {
		pkt, err = c.ReadPacket()
		if err == io.EOF {
			break
		}
		assert.NoError(err)
		assert.NotNil(pkt)
		if err != nil {
			break
		}
		if pkt != nil {
			id, _ := pkt.Header().GetInt("flood_id")
			assert.True(lastId < id)
			lastId = id
		}
	}
}

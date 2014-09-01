package e3x

import (
	"io"
	"testing"

	"github.com/stretchr/testify/suite"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports/udp"
)

type channelTestSuite struct {
	suite.Suite
	A *Endpoint
	B *Endpoint
}

func TestChannels(t *testing.T) {
	suite.Run(t, &channelTestSuite{})
}

func (c *channelTestSuite) SetupTest() {
	var (
		assert = c.Assertions
		err    error
	)

	ka, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	kb, err := cipherset.GenerateKey(0x3a)
	assert.NoError(err)

	ta, err := udp.New("127.0.0.1:8081")
	assert.NoError(err)

	tb, err := udp.New("127.0.0.1:8082")
	assert.NoError(err)

	c.A = New(cipherset.Keys{0x3a: ka})
	c.B = New(cipherset.Keys{0x3a: kb})
	c.A.AddTransport(ta)
	c.B.AddTransport(tb)

	err = c.A.Start()
	assert.NoError(err)

	err = c.B.Start()
	assert.NoError(err)
}

func (c *channelTestSuite) TearDownTest() {
	var (
		assert = c.Assertions
		err    error
	)

	err = c.A.Stop()
	assert.NoError(err)

	err = c.B.Stop()
	assert.NoError(err)
}

func (s *channelTestSuite) TestPingPong() {
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

func (s *channelTestSuite) TestFloodReliable() {
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

		for i := 0; i < 100000; i++ {
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
		if pkt != nil {
			id, _ := pkt.Header().GetInt("flood_id")
			assert.True(lastId < id)
			lastId = id
		}
	}
}

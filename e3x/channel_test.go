package e3x

import (
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

		// defer c.Close()

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

	err = c.WritePacket(&lob.Packet{Body: []byte("ping")})
	assert.NoError(err)

	pkt, err = c.ReadPacket()
	assert.NoError(err)
	assert.NotNil(pkt)
	assert.Equal("pong", string(pkt.Body))
}

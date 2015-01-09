package tests

import (
	"bytes"
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/suite"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/lob"
)

type cipherTestSuite struct {
	suite.Suite
	csid uint8
}

func Run(t *testing.T, csid uint8) {
	suite.Run(t, &cipherTestSuite{csid: csid})
}

func (s *cipherTestSuite) TestMessage() {
	var (
		assert = s.Assertions
	)

	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt0  *lob.Packet
		pkt1  *lob.Packet
		pkt2  *lob.Packet
		err   error
	)

	keyA, err = cipherset.GenerateKey(s.csid)
	assert.NoError(err)
	assert.NotNil(keyA)

	keyB, err = cipherset.GenerateKey(s.csid)
	assert.NoError(err)
	assert.NotNil(keyB)

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{s.csid: keyA})
	assert.NoError(err)
	assert.NotNil(selfA)

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{s.csid: keyB})
	assert.NoError(err)
	assert.NotNil(selfB)

	sessA, err = selfA.NewSession(map[uint8][]byte{s.csid: keyB.Public})
	assert.NoError(err)
	assert.NotNil(sessA)
	assert.False(sessA.NegotiatedEphemeralKeys())

	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessA.EncryptMessage(pkt0)
	assert.NoError(err)
	assert.NotNil(pkt1)

	pkt2, err = selfB.DecryptMessage(pkt1)
	assert.NoError(err)
	assert.NotNil(pkt2)
	assert.Equal(pkt0, pkt2)

	sessB, err = selfB.NewSession(map[uint8][]byte{s.csid: keyA.Public})
	assert.NoError(err)
	assert.NotNil(sessB)
	assert.False(sessB.NegotiatedEphemeralKeys())

	err = sessB.VerifyMessage(pkt1)
	assert.NoError(err)
	assert.True(sessB.NegotiatedEphemeralKeys())
}

func (s *cipherTestSuite) TestPacketEncryption() {
	var (
		assert = s.Assertions
	)

	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt0  *lob.Packet
		pkt1  *lob.Packet
		pkt2  *lob.Packet
		err   error
	)

	keyA, err = cipherset.GenerateKey(s.csid)
	assert.NoError(err)
	assert.NotNil(keyA)

	keyB, err = cipherset.GenerateKey(s.csid)
	assert.NoError(err)
	assert.NotNil(keyB)

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{s.csid: keyA})
	assert.NoError(err)
	assert.NotNil(selfA)

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{s.csid: keyB})
	assert.NoError(err)
	assert.NotNil(selfB)

	sessA, err = selfA.NewSession(map[uint8][]byte{s.csid: keyB.Public})
	assert.NoError(err)
	assert.NotNil(sessA)
	assert.False(sessA.NegotiatedEphemeralKeys())

	sessB, err = selfB.NewSession(map[uint8][]byte{s.csid: keyA.Public})
	assert.NoError(err)
	assert.NotNil(sessB)
	assert.False(sessB.NegotiatedEphemeralKeys())

	// Message: A => B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessA.EncryptMessage(pkt0)
	assert.NoError(err)
	assert.NotNil(pkt1)

	pkt2, err = selfB.DecryptMessage(pkt1)
	assert.NoError(err)
	assert.NotNil(pkt2)
	assert.Equal(pkt0, pkt2)

	err = sessB.VerifyMessage(pkt1)
	assert.NoError(err)
	assert.True(sessB.NegotiatedEphemeralKeys())

	// Message: A <= B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessB.EncryptMessage(pkt0)
	assert.NoError(err)
	assert.NotNil(pkt1)

	pkt2, err = selfA.DecryptMessage(pkt1)
	assert.NoError(err)
	assert.NotNil(pkt2)
	assert.Equal(pkt0, pkt2)

	err = sessA.VerifyMessage(pkt1)
	assert.NoError(err)
	assert.True(sessA.NegotiatedEphemeralKeys())

	// Packet: A => B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessA.EncryptPacket(pkt0)
	assert.NoError(err)
	assert.NotNil(pkt1)

	pkt2, err = sessB.DecryptPacket(pkt1)
	assert.NoError(err)
	assert.NotNil(pkt2)
	assert.Equal(pkt0, pkt2)

	// Packet: A <= B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessB.EncryptPacket(pkt0)
	assert.NoError(err)
	assert.NotNil(pkt1)

	pkt2, err = sessA.DecryptPacket(pkt1)
	assert.NoError(err)
	assert.NotNil(pkt2)
	assert.Equal(pkt0, pkt2)
}

func BenchmarkPacketEncryption(b *testing.B, csid uint8) {
	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt0  *lob.Packet
		pkt1  *lob.Packet
		pkt   = lob.New(bytes.Repeat([]byte{'x'}, 1024))
		err   error
	)

	keyA, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	keyB, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyA})
	if err != nil {
		panic(err)
	}

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyB})
	if err != nil {
		panic(err)
	}

	sessA, err = selfA.NewSession(map[uint8][]byte{csid: keyB.Public})
	if err != nil {
		panic(err)
	}

	sessB, err = selfB.NewSession(map[uint8][]byte{csid: keyA.Public})
	if err != nil {
		panic(err)
	}

	// Message: A => B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessA.EncryptMessage(pkt0)
	if err != nil {
		panic(err)
	}

	err = sessB.VerifyMessage(pkt1)
	if err != nil {
		panic(err)
	}

	// Message: A <= B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessB.EncryptMessage(pkt0)
	if err != nil {
		panic(err)
	}

	err = sessA.VerifyMessage(pkt1)
	if err != nil {
		panic(err)
	}

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		epkt, err := sessA.EncryptPacket(pkt)
		epkt.Free()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketDecryption(b *testing.B, csid uint8) {
	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt0  *lob.Packet
		pkt1  *lob.Packet
		pkt   = lob.New(bytes.Repeat([]byte{'x'}, 1024))
		err   error
	)

	keyA, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	keyB, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyA})
	if err != nil {
		panic(err)
	}

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyB})
	if err != nil {
		panic(err)
	}

	sessA, err = selfA.NewSession(map[uint8][]byte{csid: keyB.Public})
	if err != nil {
		panic(err)
	}

	sessB, err = selfB.NewSession(map[uint8][]byte{csid: keyA.Public})
	if err != nil {
		panic(err)
	}

	// Message: A => B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessA.EncryptMessage(pkt0)
	if err != nil {
		panic(err)
	}

	err = sessB.VerifyMessage(pkt1)
	if err != nil {
		panic(err)
	}

	// Message: A <= B
	pkt0 = lob.New([]byte("Hello World!"))
	pkt1, err = sessB.EncryptMessage(pkt0)
	if err != nil {
		panic(err)
	}

	err = sessA.VerifyMessage(pkt1)
	if err != nil {
		panic(err)
	}

	pkt, err = sessB.EncryptPacket(pkt)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		epkt, err := sessA.DecryptPacket(pkt)
		epkt.Free()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageEncryption(b *testing.B, csid uint8) {
	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		sessA *cipherset.Session
		pkt   = lob.New(bytes.Repeat([]byte{'x'}, 1024))
		err   error
	)

	keyA, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	keyB, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyA})
	if err != nil {
		panic(err)
	}

	sessA, err = selfA.NewSession(map[uint8][]byte{csid: keyB.Public})
	if err != nil {
		panic(err)
	}

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		epkt, err := sessA.EncryptMessage(pkt)
		epkt.Free()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageDecryption(b *testing.B, csid uint8) {
	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt1  *lob.Packet
		pkt   = lob.New(bytes.Repeat([]byte{'x'}, 1024))
		err   error
	)

	keyA, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	keyB, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyA})
	if err != nil {
		panic(err)
	}

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyB})
	if err != nil {
		panic(err)
	}

	sessA, err = selfA.NewSession(map[uint8][]byte{csid: keyB.Public})
	if err != nil {
		panic(err)
	}

	sessB, err = selfB.NewSession(map[uint8][]byte{csid: keyA.Public})
	if err != nil {
		panic(err)
	}

	// Message: A => B
	pkt1, err = sessA.EncryptMessage(pkt)
	if err != nil {
		panic(err)
	}

	err = sessB.VerifyMessage(pkt1)
	if err != nil {
		panic(err)
	}

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		epkt, err := selfB.DecryptMessage(pkt1)
		epkt.Free()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageVerification(b *testing.B, csid uint8) {
	var (
		keyA  *cipherset.PrivateKey
		keyB  *cipherset.PrivateKey
		selfA *cipherset.Self
		selfB *cipherset.Self
		sessA *cipherset.Session
		sessB *cipherset.Session
		pkt1  *lob.Packet
		pkt   = lob.New(bytes.Repeat([]byte{'x'}, 1024))
		err   error
	)

	keyA, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	keyB, err = cipherset.GenerateKey(csid)
	if err != nil {
		panic(err)
	}

	selfA, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyA})
	if err != nil {
		panic(err)
	}

	selfB, err = cipherset.New(map[uint8]*cipherset.PrivateKey{csid: keyB})
	if err != nil {
		panic(err)
	}

	sessA, err = selfA.NewSession(map[uint8][]byte{csid: keyB.Public})
	if err != nil {
		panic(err)
	}

	sessB, err = selfB.NewSession(map[uint8][]byte{csid: keyA.Public})
	if err != nil {
		panic(err)
	}

	// Message: A => B
	pkt1, err = sessA.EncryptMessage(pkt)
	if err != nil {
		panic(err)
	}

	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := sessB.VerifyMessage(pkt1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

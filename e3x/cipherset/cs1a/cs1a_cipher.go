// Package cs1a implements Cipher Set 1a.
package cs1a

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/telehash/gogotelehash/e3x/cipherset/cs1a/eccp"
	"github.com/telehash/gogotelehash/e3x/cipherset/cs1a/ecdh"
	"github.com/telehash/gogotelehash/e3x/cipherset/cs1a/secp160r1"
	"github.com/telehash/gogotelehash/e3x/cipherset/driver"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
)

var (
	_ driver.Driver  = (*driverImp)(nil)
	_ driver.Self    = (*selfImp)(nil)
	_ driver.Session = (*sessionImp)(nil)
)

var csidHeader = []byte{0x1a}

func init() {
	driver.Register(&driverImp{})
}

type driverImp struct{}

type selfImp struct {
	prv []byte
	x   *big.Int
	y   *big.Int
}

type sessionImp struct {
	// computed by NewSession()
	self            *selfImp
	localToken      [16]byte
	remoteKeyX      *big.Int
	remoteKeyY      *big.Int
	localLineKeyPrv []byte
	localLineKeyPub []byte
	localLineKeyX   *big.Int
	localLineKeyY   *big.Int
	messageBlock    cipher.Block

	// computed by the first VerifyMessage
	remoteToken       [16]byte
	remoteLineKeyPub  []byte
	remoteLineKeyX    *big.Int
	remoteLineKeyY    *big.Int
	lineEncryptionKey []byte
	lineDecryptionKey []byte
}

func (d *driverImp) CSID() uint8 {
	return 0x1a
}

func (d *driverImp) GenerateKey() (prv, pub []byte, err error) {
	prv, x, y, err := elliptic.GenerateKey(secp160r1.P160(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub = eccp.Marshal(secp160r1.P160(), x, y)
	return prv, pub, nil
}

func (d *driverImp) NewSelf(prv, pub []byte) (driver.Self, error) {
	if len(prv) == 0 || len(pub) == 0 {
		return nil, driver.ErrInvalidKey
	}

	self := &selfImp{}

	self.prv = make([]byte, len(prv))
	copy(self.prv, prv)

	self.x, self.y = eccp.Unmarshal(secp160r1.P160(), pub)
	if self.x == nil || self.y == nil {
		return nil, driver.ErrInvalidKey
	}

	return self, nil
}

func (s *selfImp) DecryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	if pkt.BodyLen() < 21+4+4 {
		return nil, driver.ErrInvalidMessage
	}

	var (
		ctLen    = pkt.BodyLen() - (21 + 4 + 4)
		body     = bufpool.New()
		inner    = bufpool.New().SetLen(ctLen)
		innerPkt *lob.Packet
		bodyRaw  []byte
		ephemX   *big.Int
		ephemY   *big.Int
		shared   []byte
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	var (
		remoteLineKey = bodyRaw[:21]
		iv            = bodyRaw[21 : 21+4]
		ciphertext    = bodyRaw[21+4 : 21+4+ctLen]
		aesIv         [16]byte
	)

	copy(aesIv[:], iv)

	ephemX, ephemY = eccp.Unmarshal(secp160r1.P160(), remoteLineKey)
	if ephemX == nil || ephemY == nil {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	shared = ecdh.ComputeShared(secp160r1.P160(), ephemX, ephemY, s.prv)
	if shared == nil {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	aharedSum := sha256.Sum256(shared)
	aesKey := fold(aharedSum[:], 16)
	if aesKey == nil {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	aes := cipher.NewCTR(aesBlock, aesIv[:])
	if aes == nil {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	aes.XORKeyStream(inner.RawBytes(), ciphertext)

	innerPkt, err = lob.Decode(inner)
	if err != nil {
		body.Free()
		inner.Free()
		return nil, err
	}

	body.Free()
	inner.Free()
	return innerPkt, nil
}

func (s *selfImp) NewSession(key []byte) (driver.Session, error) {
	session := &sessionImp{}
	session.self = s

	{ // copy the remote key
		if len(key) == 0 {
			return nil, driver.ErrInvalidKey
		}

		session.remoteKeyX, session.remoteKeyY = eccp.Unmarshal(secp160r1.P160(), key)
		if session.remoteKeyX == nil || session.remoteKeyY == nil {
			return nil, driver.ErrInvalidKey
		}
	}

	{ // make local line key
		prv, x, y, err := elliptic.GenerateKey(secp160r1.P160(), rand.Reader)
		if err != nil {
			return nil, err
		}
		session.localLineKeyPrv = prv
		session.localLineKeyPub = eccp.Marshal(secp160r1.P160(), x, y)
		session.localLineKeyX = x
		session.localLineKeyY = y
	}

	{ // make local token
		sha := sha256.Sum256(session.localLineKeyPub[:16])
		copy(session.localToken[:], sha[:16])
	}

	{ // make message block cipher
		shared := ecdh.ComputeShared(
			secp160r1.P160(),
			session.remoteKeyX, session.remoteKeyY,
			session.localLineKeyPrv)
		if shared == nil {
			return nil, driver.ErrInvalidMessage
		}

		aharedSum := sha256.Sum256(shared)
		aesKey := fold(aharedSum[:], 16)
		if aesKey == nil {
			return nil, driver.ErrInvalidState
		}

		messageBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}

		session.messageBlock = messageBlock
	}

	return session, nil
}

func (s *sessionImp) LocalToken() [16]byte {
	return s.localToken
}

func (s *sessionImp) RemoteToken() [16]byte {
	return s.remoteToken
}

func (s *sessionImp) NegotiatedEphemeralKeys() bool {
	return s.remoteLineKeyPub != nil
}

func (s *sessionImp) VerifyMessage(pkt *lob.Packet) error {
	if pkt.BodyLen() < 21+4+4 {
		return driver.ErrInvalidMessage
	}

	var (
		ctLen   = pkt.BodyLen() - (21 + 4 + 4)
		body    = bufpool.New()
		bodyRaw []byte
		ephemX  *big.Int
		ephemY  *big.Int
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	var (
		remoteLineKey = bodyRaw[:21]
		iv            = bodyRaw[21 : 21+4]
		mac           = bodyRaw[21+4+ctLen:]
		macKey        []byte
	)

	// make makeKey
	macKey = ecdh.ComputeShared(secp160r1.P160(),
		s.remoteKeyX, s.remoteKeyY, s.self.prv)
	macKey = append(macKey, iv...)

	// verify mac
	h := hmac.New(sha256.New, macKey)
	h.Write(bodyRaw[:21+4+ctLen])
	if subtle.ConstantTimeCompare(mac, fold(h.Sum(nil), 4)) != 1 {
		body.Free()
		return driver.ErrInvalidMessage
	}

	// verify remote line key
	if s.remoteLineKeyPub != nil && !bytes.Equal(s.remoteLineKeyPub, remoteLineKey) {
		body.Free()
		return driver.ErrSessionReset
	}

	ephemX, ephemY = eccp.Unmarshal(secp160r1.P160(), remoteLineKey)
	if ephemX == nil || ephemY == nil {
		body.Free()
		return driver.ErrInvalidMessage
	}

	// Message is valid:
	// - now set the lineKey and token
	// - make the encryption keys
	if s.remoteLineKeyPub == nil {
		// copy remote token
		s.remoteLineKeyPub = make([]byte, len(remoteLineKey))
		copy(s.remoteLineKeyPub, remoteLineKey)
		s.remoteLineKeyX = ephemX
		s.remoteLineKeyY = ephemY

		// make remote token
		sha := sha256.Sum256(remoteLineKey[:16])
		copy(s.remoteToken[:], sha[:16])

		{ // make line encryption/decryption keys
			sharedKey := ecdh.ComputeShared(
				secp160r1.P160(),
				s.remoteLineKeyX, s.remoteLineKeyY,
				s.localLineKeyPrv)

			sha := sha256.New()
			sha.Write(sharedKey)
			sha.Write(s.localLineKeyPub)
			sha.Write(s.remoteLineKeyPub)
			s.lineEncryptionKey = fold(sha.Sum(nil), 16)

			sha.Reset()
			sha.Write(sharedKey)
			sha.Write(s.remoteLineKeyPub)
			sha.Write(s.localLineKeyPub)
			s.lineDecryptionKey = fold(sha.Sum(nil), 16)
		}
	}

	body.Free()
	return nil
}

func (s *sessionImp) EncryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	var (
		inner   *bufpool.Buffer
		outer   *lob.Packet
		body    = bufpool.New()
		bodyRaw []byte
		ctLen   int
		err     error
	)

	inner, err = lob.Encode(pkt)
	if err != nil {
		body.Free()
		return nil, err
	}
	ctLen = inner.Len()

	body.SetLen(21 + 4 + ctLen + 4)
	bodyRaw = body.RawBytes()

	// copy public senderLineKey
	copy(bodyRaw[:21], s.localLineKeyPub)

	// copy the nonce
	_, err = io.ReadFull(rand.Reader, bodyRaw[21:21+4])
	if err != nil {
		body.Free()
		inner.Free()
		return nil, err
	}

	{ // encrypt inner
		var aesIv [16]byte
		copy(aesIv[:], bodyRaw[21:21+4])

		aes := cipher.NewCTR(s.messageBlock, aesIv[:])
		if aes == nil {
			body.Free()
			inner.Free()
			return nil, driver.ErrInvalidMessage
		}

		aes.XORKeyStream(bodyRaw[21+4:21+4+ctLen], inner.RawBytes())
	}

	{ // compute HMAC
		macKey := ecdh.ComputeShared(secp160r1.P160(),
			s.remoteKeyX, s.remoteKeyY, s.self.prv)
		macKey = append(macKey, bodyRaw[21:21+4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(bodyRaw[:21+4+ctLen])
		sum := h.Sum(nil)
		copy(bodyRaw[21+4+ctLen:], fold(sum, 4))
	}

	outer = lob.New(body.RawBytes())
	outer.Header().Bytes = csidHeader

	inner.Free()
	body.Free()
	return outer, nil
}

func (s *sessionImp) EncryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	var (
		outer   *lob.Packet
		inner   *bufpool.Buffer
		body    *bufpool.Buffer
		bodyRaw []byte
		nonce   [16]byte
		ctLen   int
		err     error
	)

	if s.remoteLineKeyPub == nil {
		return nil, driver.ErrInvalidState
	}
	if pkt == nil {
		return nil, nil
	}

	// encode inner packet
	inner, err = lob.Encode(pkt)
	if err != nil {
		return nil, err
	}

	ctLen = inner.Len()

	// make nonce
	_, err = io.ReadFull(rand.Reader, nonce[:4])
	if err != nil {
		inner.Free()
		return nil, err
	}

	// alloc enough space
	body = bufpool.New().SetLen(16 + 4 + ctLen + 4)
	bodyRaw = body.RawBytes()

	// copy token
	copy(bodyRaw[:16], s.remoteToken[:])

	// copy nonce
	copy(bodyRaw[16:16+4], nonce[:])

	{ // encrypt inner
		aesBlock, err := aes.NewCipher(s.lineEncryptionKey)
		if err != nil {
			inner.Free()
			body.Free()
			return nil, err
		}

		aes := cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			inner.Free()
			body.Free()
			return nil, driver.ErrInvalidMessage
		}

		aes.XORKeyStream(bodyRaw[16+4:16+4+ctLen], inner.RawBytes())
	}

	{ // compute HMAC
		macKey := append(s.lineEncryptionKey, bodyRaw[16:16+4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(bodyRaw[16+4 : 16+4+ctLen])
		sum := h.Sum(nil)
		copy(bodyRaw[16+4+ctLen:], fold(sum, 4))
	}

	outer = lob.New(body.RawBytes())

	inner.Free()
	body.Free()
	return outer, nil
}

func (s *sessionImp) DecryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	if s.remoteLineKeyPub == nil {
		return nil, driver.ErrInvalidState
	}
	if pkt == nil {
		return nil, nil
	}

	if !pkt.Header().IsZero() || pkt.BodyLen() < 16+4+4 {
		return nil, driver.ErrInvalidPacket
	}

	var (
		nonce    [16]byte
		bodyRaw  []byte
		innerRaw []byte
		innerLen = pkt.BodyLen() - (16 + 4 + 4)
		body     = bufpool.New()
		inner    = bufpool.New().SetLen(innerLen)
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()
	innerRaw = inner.RawBytes()

	// compare token
	if !bytes.Equal(bodyRaw[:16], s.localToken[:]) {
		inner.Free()
		body.Free()
		return nil, driver.ErrInvalidPacket
	}

	// copy nonce
	copy(nonce[:], bodyRaw[16:16+4])

	{ // verify hmac
		mac := bodyRaw[16+4+innerLen:]

		macKey := append(s.lineDecryptionKey, nonce[:4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(bodyRaw[16+4 : 16+4+innerLen])
		if subtle.ConstantTimeCompare(mac, fold(h.Sum(nil), 4)) != 1 {
			inner.Free()
			body.Free()
			return nil, driver.ErrInvalidPacket
		}
	}

	{ // decrypt inner
		aesBlock, err := aes.NewCipher(s.lineDecryptionKey)
		if err != nil {
			inner.Free()
			body.Free()
			return nil, err
		}

		aes := cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			inner.Free()
			body.Free()
			return nil, driver.ErrInvalidPacket
		}

		aes.XORKeyStream(innerRaw, bodyRaw[16+4:16+4+innerLen])
	}

	innerPkt, err := lob.Decode(inner)
	if err != nil {
		inner.Free()
		body.Free()
		return nil, err
	}

	inner.Free()
	body.Free()

	return innerPkt, nil
}

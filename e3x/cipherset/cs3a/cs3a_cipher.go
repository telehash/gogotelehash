package cs3a

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"sync"
	"sync/atomic"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/golang.org/x/crypto/nacl/box"
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/golang.org/x/crypto/poly1305"

	"github.com/telehash/gogotelehash/e3x/cipherset/driver"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
)

var (
	_ driver.Driver  = (*driverImp)(nil)
	_ driver.Self    = (*selfImp)(nil)
	_ driver.Session = (*sessionImp)(nil)
)

const (
	lenKey   = 32
	lenNonce = 24
	lenAuth  = 16
	lenToken = 16
)

var csidHeader = []byte{0x3a}
var sha256Pool = sync.Pool{
	New: func() interface{} { return sha256.New() },
}

func init() {
	driver.Register(&driverImp{})
}

type driverImp struct {
}

type selfImp struct {
	prv *[lenKey]byte
	pub *[lenKey]byte
}

type sessionImp struct {
	// computed by NewSession()
	self            *selfImp
	localToken      [lenToken]byte
	remoteKey       [lenKey]byte
	localLineKeyPrv [lenKey]byte
	localLineKeyPub [lenKey]byte
	noncePrefix     [lenNonce - 8]byte
	nonceSuffix     uint64

	// computed by the first VerifyMessage
	remoteLineKey     *[lenKey]byte
	remoteToken       [lenToken]byte
	lineEncryptionKey [lenKey]byte
	lineDecryptionKey [lenKey]byte
}

func (d *driverImp) CSID() uint8 {
	return 0x3a
}

func (d *driverImp) GenerateKey() (prv, pub []byte, err error) {
	pubKey, prvKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	prv = make([]byte, lenKey)
	pub = make([]byte, lenKey)
	copy(prv, prvKey[:])
	copy(pub, pubKey[:])

	return prv, pub, nil
}

func (d *driverImp) NewSelf(prv, pub []byte) (driver.Self, error) {
	if len(prv) != lenKey || len(pub) != lenKey {
		return nil, driver.ErrInvalidKey
	}

	prvKey := new([lenKey]byte)
	pubKey := new([lenKey]byte)
	copy(prvKey[:], prv)
	copy(pubKey[:], pub)

	return &selfImp{prv: prvKey, pub: pubKey}, nil
}

func (s *selfImp) DecryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	if pkt.BodyLen() < lenKey+lenNonce+lenAuth {
		return nil, driver.ErrInvalidMessage
	}

	var (
		ctLen         = pkt.BodyLen() - (lenKey + lenNonce + lenAuth)
		body          = bufpool.New()
		inner         = bufpool.New().SetLen(ctLen)
		innerPkt      *lob.Packet
		innerRaw      []byte
		bodyRaw       []byte
		nonce         [lenNonce]byte
		agreedKey     [lenKey]byte
		remoteLineKey [lenKey]byte
		ciphertext    []byte
		ok            bool
		err           error
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	copy(remoteLineKey[:], bodyRaw[:lenKey])
	copy(nonce[:], bodyRaw[lenKey:lenKey+lenNonce])
	ciphertext = bodyRaw[lenKey+lenNonce : lenKey+lenNonce+ctLen]

	// make agreedKey
	box.Precompute(&agreedKey, &remoteLineKey, s.prv)

	// decode BODY
	innerRaw, ok = box.OpenAfterPrecomputation(
		inner.RawBytes()[:0], ciphertext, &nonce, &agreedKey)
	if !ok {
		body.Free()
		inner.Free()
		return nil, driver.ErrInvalidMessage
	}

	inner.SetLen(len(innerRaw))
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
		if len(key) != lenKey {
			return nil, driver.ErrInvalidKey
		}
		copy(session.remoteKey[:], key)
	}

	{ // make a random nonce prefix
		_, err := io.ReadFull(rand.Reader, session.noncePrefix[:])
		if err != nil {
			return nil, err
		}
	}

	{ // make local line keys
		pubKey, prvKey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		session.localLineKeyPrv = *prvKey
		session.localLineKeyPub = *pubKey
	}

	{ // make the local token
		sha := sha256.Sum256(session.localLineKeyPub[:lenToken])
		copy(session.localToken[:], sha[:lenToken])
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
	return s.remoteLineKey != nil
}

func (s *sessionImp) VerifyMessage(pkt *lob.Packet) error {
	if pkt.BodyLen() < lenKey+lenNonce+lenAuth {
		return driver.ErrInvalidMessage
	}

	var (
		ctLen         = pkt.BodyLen() - (lenKey + lenNonce + lenAuth)
		body          = bufpool.New()
		bodyRaw       []byte
		remoteLineKey [lenKey]byte
		mac           [lenAuth]byte
		macKey        [lenKey]byte
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	copy(mac[:], bodyRaw[lenKey+lenNonce+ctLen:])
	copy(remoteLineKey[:], bodyRaw[:lenKey])

	{ // make macKey
		box.Precompute(&macKey, &s.remoteKey, s.self.prv)

		var (
			sha = sha256Pool.Get().(hash.Hash)
		)

		sha.Write(bodyRaw[lenKey : lenKey+lenNonce])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])

		sha.Reset()
		sha256Pool.Put(sha)
	}

	// validate mac
	if !poly1305.Verify(&mac, bodyRaw[:lenKey+lenNonce+ctLen], &macKey) {
		body.Free()
		return driver.ErrInvalidMessage
	}

	// verify remote line key
	if s.remoteLineKey != nil && !bytes.Equal(s.remoteLineKey[:], remoteLineKey[:]) {
		body.Free()
		return driver.ErrSessionReset
	}

	// Message is valid:
	// - now set the lineKey and token
	// - make the encryption keys
	if s.remoteLineKey == nil {
		// copy remote token
		s.remoteLineKey = new([lenKey]byte)
		copy(s.remoteLineKey[:], remoteLineKey[:])

		// make remote token
		sha := sha256.Sum256(remoteLineKey[:lenToken])
		copy(s.remoteToken[:], sha[:lenToken])

		{ // make line encryption/decryption keys
			var sharedKey [lenKey]byte
			box.Precompute(&sharedKey, &remoteLineKey, &s.localLineKeyPrv)

			sha := sha256Pool.Get().(hash.Hash)
			sha.Write(sharedKey[:])
			sha.Write(s.localLineKeyPub[:])
			sha.Write(s.remoteLineKey[:])
			sha.Sum(s.lineEncryptionKey[:0])

			sha.Reset()
			sha.Write(sharedKey[:])
			sha.Write(s.remoteLineKey[:])
			sha.Write(s.localLineKeyPub[:])
			sha.Sum(s.lineDecryptionKey[:0])

			sha.Reset()
			sha256Pool.Put(sha)
		}
	}

	body.Free()
	return nil
}

func (s *sessionImp) EncryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	var (
		inner       *bufpool.Buffer
		outer       *lob.Packet
		body        = bufpool.New()
		bodyRaw     []byte
		nonce       [lenNonce]byte
		agreedKey   [lenKey]byte
		macKey      [lenKey]byte
		mac         [lenAuth]byte
		nonceSuffix uint64
		ctLen       int
	)

	inner, err := lob.Encode(pkt)
	if err != nil {
		body.Free()
		return nil, err
	}

	body.SetLen(lenKey + lenNonce + inner.Len() + box.Overhead + lenAuth)
	bodyRaw = body.RawBytes()

	// make new nonce
	copy(nonce[:], s.noncePrefix[:])
	nonceSuffix = atomic.AddUint64(&s.nonceSuffix, 1)
	binary.BigEndian.PutUint64(nonce[lenNonce-8:], nonceSuffix)

	// copy public line key
	copy(bodyRaw[:lenKey], s.localLineKeyPub[:])

	// copy nonce
	copy(bodyRaw[lenKey:lenKey+lenNonce], nonce[:])

	// make the agreedKey
	// this can be prcomputed during NewSession()
	box.Precompute(&agreedKey, &s.remoteKey, &s.localLineKeyPrv)

	// encrypt p
	ctLen = len(box.SealAfterPrecomputation(
		bodyRaw[lenKey+lenNonce:lenKey+lenNonce], inner.RawBytes(), &nonce, &agreedKey))

	{ // make macKey
		box.Precompute(&macKey, &s.remoteKey, s.self.prv)

		var (
			sha = sha256Pool.Get().(hash.Hash)
		)

		sha.Write(nonce[:])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])

		sha.Reset()
		sha256Pool.Put(sha)
	}

	// sign the message
	poly1305.Sum(&mac, bodyRaw[:lenKey+lenNonce+ctLen], &macKey)
	copy(bodyRaw[lenKey+lenNonce+ctLen:], mac[:])

	body.SetLen(lenKey + lenNonce + ctLen + lenAuth)

	outer = lob.New(body.RawBytes())
	outer.Header().Bytes = csidHeader

	inner.Free()
	body.Free()
	return outer, nil
}

func (s *sessionImp) EncryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	var (
		outer       *lob.Packet
		inner       *bufpool.Buffer
		body        *bufpool.Buffer
		bodyRaw     []byte
		nonce       [lenNonce]byte
		nonceSuffix uint64
		ctLen       int
		err         error
	)

	if s.remoteLineKey == nil {
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

	// make nonce
	copy(nonce[:], s.noncePrefix[:])
	nonceSuffix = atomic.AddUint64(&s.nonceSuffix, 1)
	binary.BigEndian.PutUint64(nonce[lenNonce-8:], nonceSuffix)

	// alloc enough space
	body = bufpool.New().SetLen(lenToken + lenNonce + inner.Len() + box.Overhead)
	bodyRaw = body.RawBytes()

	// copy token
	copy(bodyRaw[:lenToken], s.remoteToken[:])

	// copy nonce
	copy(bodyRaw[lenToken:lenToken+lenNonce], nonce[:])

	// encrypt inner packet
	ctLen = len(box.SealAfterPrecomputation(
		bodyRaw[lenToken+lenNonce:lenToken+lenNonce], inner.RawBytes(), &nonce, &s.lineEncryptionKey))
	body.SetLen(lenToken + lenNonce + ctLen)

	outer = lob.New(body.RawBytes())
	inner.Free()
	body.Free()

	return outer, nil
}

func (s *sessionImp) DecryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	if s.remoteLineKey == nil {
		return nil, driver.ErrInvalidState
	}
	if pkt == nil {
		return nil, nil
	}

	if !pkt.Header().IsZero() || pkt.BodyLen() < lenToken+lenNonce {
		return nil, driver.ErrInvalidPacket
	}

	var (
		nonce    [lenNonce]byte
		bodyRaw  []byte
		innerRaw []byte
		innerPkt *lob.Packet
		body     = bufpool.New()
		inner    = bufpool.New()
		ok       bool
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()
	innerRaw = inner.RawBytes()

	// compare token
	if !bytes.Equal(bodyRaw[:lenToken], s.localToken[:]) {
		inner.Free()
		body.Free()
		return nil, driver.ErrInvalidPacket
	}

	// copy nonce
	copy(nonce[:], bodyRaw[lenToken:lenToken+lenNonce])

	// decrypt inner packet
	innerRaw, ok = box.OpenAfterPrecomputation(
		innerRaw[:0], bodyRaw[lenToken+lenNonce:], &nonce, &s.lineDecryptionKey)
	if !ok {
		inner.Free()
		body.Free()
		return nil, driver.ErrInvalidPacket
	}
	inner.SetLen(len(innerRaw))

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

// Package cs1a implements Cipher Set 1a.
package cs1a

import (
	"bytes"
	"crypto/aes"
	Cipher "crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"
	"sync"

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
	if len(p) < 21+4+4 {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen    = pkt.BodyLen() - (21 + 4 + 4)
		body     = bufpool.New()
		inner    = bufpool.New().SetLen(ctLen)
		innerPkt *lob.Packet
		innerRaw []byte
		bodyRaw  []byte
		ephemX   *big.Int
		ephemY   *big.Int
		shared   []byte

		out              = make([]byte, ctLen)
		cs1aLocalKey, _  = localKey.(*key)
		cs1aRemoteKey, _ = remoteKey.(*key)
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	var (
		remoteLineKey = bodyRaw[:21]
		iv            = bodyRaw[21 : 21+4]
		ciphertext    = bodyRaw[21+4 : 21+4+ctLen]
		mac           = bodyRaw[21+4+ctLen:]
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
	if len(p) < 21+4+4 {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen   = pkt.BodyLen() - (21 + 4 + 4)
		body    = bufpool.New()
		bodyRaw []byte
		ephemX  *big.Int
		ephemY  *big.Int
		shared  []byte

		out              = make([]byte, ctLen)
		cs1aLocalKey, _  = localKey.(*key)
		cs1aRemoteKey, _ = remoteKey.(*key)
	)

	pkt.Body(body.SetLen(pkt.BodyLen()).RawBytes()[:0])
	bodyRaw = body.RawBytes()

	var (
		remoteLineKey = bodyRaw[:21]
		iv            = bodyRaw[21 : 21+4]
		ciphertext    = bodyRaw[21+4 : 21+4+ctLen]
		mac           = bodyRaw[21+4+ctLen:]
		aesIv         [16]byte
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
		s.remoteLineKeyPub = new([]byte, len(remoteLineKey))
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
		shared := ecdh.ComputeShared(
			secp160r1.P160(),
			s.remoteKeyX, s.remoteKeyY,
			s.localLineKeyPrv)
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
			return nil, err
		}

		var aesIv [16]byte
		copy(aesIv[:], bodyRaw[21:21+4])

		aes := Cipher.NewCTR(aesBlock, aesIv[:])
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

// ========================================================================== //

func (c *cipher) NewState(localKey cipherset.Key) (cipherset.State, error) {
	if k, ok := localKey.(*key); ok && k != nil && k.CanEncrypt() && k.CanSign() {
		s := &state{localKey: k}
		s.update()
		return s, nil
	}
	return nil, cipherset.ErrInvalidKey
}

func (c *cipher) DecryptMessage(localKey, remoteKey cipherset.Key, p []byte) ([]byte, error) {
	if len(p) < 21+4+4 {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen            = len(p) - (21 + 4 + 4)
		out              = make([]byte, ctLen)
		cs1aLocalKey, _  = localKey.(*key)
		cs1aRemoteKey, _ = remoteKey.(*key)
		remoteLineKey    = p[:21]
		iv               = p[21 : 21+4]
		ciphertext       = p[21+4 : 21+4+ctLen]
		mac              = p[21+4+ctLen:]
	)

	if cs1aLocalKey == nil || cs1aRemoteKey == nil {
		return nil, cipherset.ErrInvalidState
	}

	{ // verify mac
		macKey := ecdh.ComputeShared(secp160r1.P160(),
			cs1aRemoteKey.pub.x, cs1aRemoteKey.pub.y, cs1aLocalKey.prv.d)
		macKey = append(macKey, iv...)

		h := hmac.New(sha256.New, macKey)
		h.Write(p[:21+4+ctLen])
		if subtle.ConstantTimeCompare(mac, fold(h.Sum(nil), 4)) != 1 {
			return nil, cipherset.ErrInvalidMessage
		}
	}

	{ // descrypt inner
		ephemX, ephemY := eccp.Unmarshal(secp160r1.P160(), remoteLineKey)
		if ephemX == nil || ephemY == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		shared := ecdh.ComputeShared(secp160r1.P160(), ephemX, ephemY, cs1aLocalKey.prv.d)
		if shared == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aharedSum := sha256.Sum256(shared)
		aesKey := fold(aharedSum[:], 16)
		if aesKey == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		var aesIv [16]byte
		copy(aesIv[:], iv)

		aes := Cipher.NewCTR(aesBlock, aesIv[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aes.XORKeyStream(out, ciphertext)
	}

	return out, nil
}

func (c *cipher) DecryptHandshake(localKey cipherset.Key, p []byte) (cipherset.Handshake, error) {
	if len(p) < 21+4+4 {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen             = len(p) - (21 + 4 + 4)
		out               = bufpool.New()
		cs1aLocalKey, _   = localKey.(*key)
		remoteKey         *key
		remoteLineKey     *key
		hshake            *handshake
		remoteLineKeyData = p[:21]
		iv                = p[21 : 21+4]
		ciphertext        = p[21+4 : 21+4+ctLen]
		mac               = p[21+4+ctLen:]
	)

	if cs1aLocalKey == nil {
		return nil, cipherset.ErrInvalidState
	}

	{ // decrypt inner
		ephemX, ephemY := eccp.Unmarshal(secp160r1.P160(), remoteLineKeyData)
		if ephemX == nil || ephemY == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		shared := ecdh.ComputeShared(secp160r1.P160(), ephemX, ephemY, cs1aLocalKey.prv.d)
		if shared == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aharedSum := sha256.Sum256(shared)
		aesKey := fold(aharedSum[:], 16)
		if aesKey == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		var aesIv [16]byte
		copy(aesIv[:], iv)

		aes := Cipher.NewCTR(aesBlock, aesIv[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		out.SetLen(ctLen)
		aes.XORKeyStream(out.RawBytes(), ciphertext)
		remoteLineKey = &key{}
		remoteLineKey.pub.x, remoteLineKey.pub.y = ephemX, ephemY
	}

	{ // decode inner
		inner, err := lob.Decode(out)
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		at, hasAt := inner.Header().GetUint32("at")
		if !hasAt {
			return nil, cipherset.ErrInvalidMessage
		}

		delete(inner.Header().Extra, "at")

		parts, err := cipherset.PartsFromHeader(inner.Header())
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		if inner.BodyLen() != 21 {
			return nil, cipherset.ErrInvalidMessage
		}

		remoteKey = &key{}
		remoteKey.pub.x, remoteKey.pub.y = eccp.Unmarshal(secp160r1.P160(), inner.Body(nil))
		if !remoteKey.CanEncrypt() {
			return nil, cipherset.ErrInvalidMessage
		}

		hshake = &handshake{}
		hshake.at = at
		hshake.key = remoteKey
		hshake.lineKey = remoteLineKey
		hshake.parts = parts
	}

	{ // verify mac
		var nonce [16]byte
		copy(nonce[:], iv)

		macKey := ecdh.ComputeShared(secp160r1.P160(),
			remoteKey.pub.x, remoteKey.pub.y, cs1aLocalKey.prv.d)
		macKey = append(macKey, nonce[:]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(p[:21+4+ctLen])
		if subtle.ConstantTimeCompare(mac, fold(h.Sum(nil), 4)) != 1 {
			return nil, cipherset.ErrInvalidMessage
		}
	}

	return hshake, nil
}

type state struct {
	mtx               sync.RWMutex
	localKey          *key
	remoteKey         *key
	localLineKey      *key
	remoteLineKey     *key
	localToken        *cipherset.Token
	remoteToken       *cipherset.Token
	lineEncryptionKey []byte
	lineDecryptionKey []byte
}

func (*state) CSID() uint8 { return 0x1a }

func (s *state) IsHigh() bool {
	if s.localKey != nil && s.remoteKey != nil {
		return s.localKey.pub.x.Cmp(s.remoteKey.pub.x) > 0
	}
	return false
}

func (s *state) LocalToken() cipherset.Token {
	if s.localToken != nil {
		return *s.localToken
	}
	return cipherset.ZeroToken
}

func (s *state) RemoteToken() cipherset.Token {
	if s.remoteToken != nil {
		return *s.remoteToken
	}
	return cipherset.ZeroToken
}

func (s *state) SetRemoteKey(remoteKey cipherset.Key) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if k, ok := remoteKey.(*key); ok && k != nil && k.CanEncrypt() {
		s.remoteKey = k
		s.update()
		return nil
	}

	return cipherset.ErrInvalidKey
}

func (s *state) setRemoteLineKey(k *key) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.remoteLineKey = k
	s.update()
}

func (s *state) update() {
	// generate a local line Key
	if s.localLineKey == nil {
		s.localLineKey, _ = generateKey()
	}

	// make local token
	if s.localToken == nil && s.localLineKey != nil {
		s.localToken = new(cipherset.Token)
		sha := sha256.Sum256(s.localLineKey.Public()[:16])
		copy((*s.localToken)[:], sha[:16])
	}

	// make remote token
	if s.remoteToken == nil && s.remoteLineKey != nil {
		s.remoteToken = new(cipherset.Token)
		sha := sha256.Sum256(s.remoteLineKey.Public()[:16])
		copy((*s.remoteToken)[:], sha[:16])
	}

	// generate line keys
	if s.localToken != nil && s.remoteToken != nil &&
		(s.lineEncryptionKey == nil || s.lineDecryptionKey == nil) {
		sharedKey := ecdh.ComputeShared(
			secp160r1.P160(),
			s.remoteLineKey.pub.x, s.remoteLineKey.pub.y,
			s.localLineKey.prv.d)

		sha := sha256.New()
		sha.Write(sharedKey)
		sha.Write(s.localLineKey.Public())
		sha.Write(s.remoteLineKey.Public())
		s.lineEncryptionKey = fold(sha.Sum(nil), 16)

		sha.Reset()
		sha.Write(sharedKey)
		sha.Write(s.remoteLineKey.Public())
		sha.Write(s.localLineKey.Public())
		s.lineDecryptionKey = fold(sha.Sum(nil), 16)
	}
}

func (s *state) NeedsRemoteKey() bool {
	return s.remoteKey == nil
}

func (s *state) CanEncryptMessage() bool {
	return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanEncryptHandshake() bool {
	return s.CanEncryptMessage()
}

func (s *state) CanEncryptPacket() bool {
	return s.lineEncryptionKey != nil && s.remoteToken != nil
}

func (s *state) CanDecryptMessage() bool {
	return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanDecryptHandshake() bool {
	return s.localKey != nil && s.localLineKey != nil
}

func (s *state) CanDecryptPacket() bool {
	return s.lineDecryptionKey != nil && s.localToken != nil
}

func (s *state) EncryptMessage(in []byte) ([]byte, error) {
	var (
		ctLen = len(in)
		out   = bufpool.New().SetLen(21 + 4 + ctLen + 4)
		raw   = out.RawBytes()
	)

	if !s.CanEncryptMessage() {
		panic("unable to encrypt message")
	}

	// copy public senderLineKey
	copy(raw[:21], s.localLineKey.Public())

	// copy the nonce
	_, err := io.ReadFull(rand.Reader, raw[21:21+4])
	if err != nil {
		return nil, err
	}

	{ // encrypt inner
		shared := ecdh.ComputeShared(
			secp160r1.P160(),
			s.remoteKey.pub.x, s.remoteKey.pub.y,
			s.localLineKey.prv.d)
		if shared == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aharedSum := sha256.Sum256(shared)
		aesKey := fold(aharedSum[:], 16)
		if aesKey == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aesBlock, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}

		var aesIv [16]byte
		copy(aesIv[:], raw[21:21+4])

		aes := Cipher.NewCTR(aesBlock, aesIv[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aes.XORKeyStream(raw[21+4:21+4+ctLen], in)
	}

	{ // compute HMAC
		macKey := ecdh.ComputeShared(secp160r1.P160(),
			s.remoteKey.pub.x, s.remoteKey.pub.y, s.localKey.prv.d)
		macKey = append(macKey, raw[21:21+4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(raw[:21+4+ctLen])
		sum := h.Sum(nil)
		copy(raw[21+4+ctLen:], fold(sum, 4))
	}

	out.SetLen(21 + 4 + ctLen + 4)

	return out.Get(nil), nil
}

func (s *state) EncryptHandshake(at uint32, compact cipherset.Parts) ([]byte, error) {
	pkt := lob.New(s.localKey.Public())
	compact.ApplyToHeader(pkt.Header())
	pkt.Header().SetUint32("at", at)
	data, err := lob.Encode(pkt)
	if err != nil {
		return nil, err
	}
	return s.EncryptMessage(data.Get(nil))
}

func (s *state) ApplyHandshake(h cipherset.Handshake) bool {
	var (
		hs, _ = h.(*handshake)
	)

	if hs == nil {
		return false
	}

	if s.remoteKey != nil && !bytes.Equal(s.remoteKey.Public(), hs.key.Public()) {
		return false
	}

	if s.remoteLineKey != nil && !bytes.Equal(s.remoteLineKey.Public(), hs.lineKey.Public()) {
		s.remoteLineKey = nil
		s.remoteToken = nil
		s.lineDecryptionKey = nil
		s.lineEncryptionKey = nil
	}

	s.setRemoteLineKey(hs.lineKey)
	if s.remoteKey == nil {
		s.SetRemoteKey(hs.key)
	}
	return true
}

func (s *state) EncryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	var (
		outer   *lob.Packet
		inner   *bufpool.Buffer
		body    *bufpool.Buffer
		bodyRaw []byte
		nonce   [16]byte
		ctLen   int
		err     error
	)

	if !s.CanEncryptPacket() {
		return nil, cipherset.ErrInvalidState
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
		return nil, err
	}

	// alloc enough space
	body = bufpool.New().SetLen(16 + 4 + ctLen + 4)
	bodyRaw = body.RawBytes()

	// copy token
	copy(bodyRaw[:16], (*s.remoteToken)[:])

	// copy nonce
	copy(bodyRaw[16:16+4], nonce[:])

	{ // encrypt inner
		aesBlock, err := aes.NewCipher(s.lineEncryptionKey)
		if err != nil {
			return nil, err
		}

		aes := Cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
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

func (s *state) DecryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if !s.CanDecryptPacket() {
		return nil, cipherset.ErrInvalidState
	}
	if pkt == nil {
		return nil, nil
	}

	if !pkt.Header().IsZero() || pkt.BodyLen() < 16+4+4 {
		return nil, cipherset.ErrInvalidPacket
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
	if !bytes.Equal(bodyRaw[:16], (*s.localToken)[:]) {
		inner.Free()
		body.Free()
		return nil, cipherset.ErrInvalidPacket
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
			return nil, cipherset.ErrInvalidPacket
		}
	}

	{ // decrypt inner
		aesBlock, err := aes.NewCipher(s.lineDecryptionKey)
		if err != nil {
			inner.Free()
			body.Free()
			return nil, err
		}

		aes := Cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			inner.Free()
			body.Free()
			return nil, cipherset.ErrInvalidPacket
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

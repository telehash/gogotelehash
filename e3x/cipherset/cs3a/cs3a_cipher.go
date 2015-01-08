package cs3a

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/golang.org/x/crypto/nacl/box"
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/golang.org/x/crypto/poly1305"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/util/base32util"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/lob"
)

var (
	_ cipherset.Cipher    = (*cipher)(nil)
	_ cipherset.State     = (*state)(nil)
	_ cipherset.Key       = (*key)(nil)
	_ cipherset.Handshake = (*handshake)(nil)
)

const (
	lenKey   = 32
	lenNonce = 24
	lenAuth  = 16
	lenToken = 16
)

func init() {
	cipherset.Register(0x3a, &cipher{})
}

type cipher struct{}

type handshake struct {
	key     *key
	lineKey *key
	parts   cipherset.Parts
	at      uint32
}

func (h *handshake) Parts() cipherset.Parts {
	return h.parts
}

func (h *handshake) PublicKey() cipherset.Key {
	return h.key
}

func (h *handshake) At() uint32 { return h.at }
func (*handshake) CSID() uint8  { return 0x3a }
func (*cipher) CSID() uint8     { return 0x3a }

func (c *cipher) DecodeKeyBytes(pub, prv []byte) (cipherset.Key, error) {
	var (
		pubKey *[lenKey]byte
		prvKey *[lenKey]byte
	)

	if len(pub) != 0 {
		if len(pub) != lenKey {
			return nil, cipherset.ErrInvalidKey
		}
		pubKey = new([lenKey]byte)
		copy((*pubKey)[:], pub)
	}

	if len(prv) != 0 {
		if len(prv) != lenKey {
			return nil, cipherset.ErrInvalidKey
		}
		prvKey = new([lenKey]byte)
		copy((*prvKey)[:], prv)
	}

	return &key{pub: pubKey, prv: prvKey}, nil
}

func (c *cipher) GenerateKey() (cipherset.Key, error) {
	return generateKey()
}

func (c *cipher) NewState(localKey cipherset.Key) (cipherset.State, error) {
	if k, ok := localKey.(*key); ok && k != nil && k.CanEncrypt() && k.CanSign() {
		s := &state{localKey: k}
		s.update()
		return s, nil
	}
	return nil, cipherset.ErrInvalidKey
}

func (c *cipher) DecryptMessage(localKey, remoteKey cipherset.Key, p []byte) ([]byte, error) {
	if len(p) < lenKey+lenNonce+lenAuth {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen            = len(p) - (lenKey + lenNonce + lenAuth)
		out              = make([]byte, ctLen)
		cs3aLocalKey, _  = localKey.(*key)
		cs3aRemoteKey, _ = remoteKey.(*key)
		mac              [lenAuth]byte
		nonce            [lenNonce]byte
		macKey           [lenKey]byte
		agreedKey        [lenKey]byte
		remoteLineKey    [lenKey]byte
		ciphertext       []byte
		ok               bool
	)

	if cs3aLocalKey == nil || cs3aRemoteKey == nil {
		return nil, cipherset.ErrInvalidState
	}

	copy(remoteLineKey[:], p[:lenKey])
	copy(nonce[:], p[lenKey:lenKey+lenNonce])
	copy(mac[:], p[lenKey+lenNonce+ctLen:])
	ciphertext = p[lenKey+lenNonce : lenKey+lenNonce+ctLen]

	{ // make macKey
		box.Precompute(&macKey, cs3aRemoteKey.pub, cs3aLocalKey.prv)

		var (
			sha = sha256.New()
		)

		sha.Write(p[lenKey : lenKey+lenNonce])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])
	}

	if !poly1305.Verify(&mac, p[:lenKey+lenNonce+ctLen], &macKey) {
		return nil, cipherset.ErrInvalidMessage
	}

	// make agreedKey
	box.Precompute(&agreedKey, &remoteLineKey, cs3aLocalKey.prv)

	// decode BODY
	out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, &agreedKey)
	if !ok {
		return nil, cipherset.ErrInvalidMessage
	}

	return out, nil
}

func (c *cipher) DecryptHandshake(localKey cipherset.Key, p []byte) (cipherset.Handshake, error) {
	if len(p) < lenKey+lenNonce+lenAuth {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen           = len(p) - (lenKey + lenNonce + lenAuth)
		out             = make([]byte, ctLen)
		handshake       = &handshake{}
		cs3aLocalKey, _ = localKey.(*key)
		at              uint32
		hasAt           bool
		mac             [lenAuth]byte
		nonce           [lenNonce]byte
		macKey          [lenKey]byte
		agreedKey       [lenKey]byte
		remoteKey       [lenKey]byte
		remoteLineKey   [lenKey]byte
		ciphertext      []byte
		ok              bool
	)

	if cs3aLocalKey == nil {
		return nil, cipherset.ErrInvalidState
	}

	copy(remoteLineKey[:], p[:lenKey])
	copy(nonce[:], p[lenKey:lenKey+lenNonce])
	copy(mac[:], p[lenKey+lenNonce+ctLen:])
	ciphertext = p[lenKey+lenNonce : lenKey+lenNonce+ctLen]

	// make agreedKey
	box.Precompute(&agreedKey, &remoteLineKey, cs3aLocalKey.prv)

	// decode BODY
	out, ok = box.OpenAfterPrecomputation(out[:0], ciphertext, &nonce, &agreedKey)
	if !ok {
		return nil, cipherset.ErrInvalidMessage
	}

	{ // decode inner
		inner, err := lob.Decode(out)
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		at, hasAt = inner.Header().GetUint32("at")
		if !hasAt {
			return nil, cipherset.ErrInvalidMessage
		}

		delete(inner.Header().Extra, "at")

		parts, err := cipherset.PartsFromHeader(inner.Header())
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		if len(inner.Body) != lenKey {
			return nil, cipherset.ErrInvalidMessage
		}
		copy(remoteKey[:], inner.Body)

		handshake.at = at
		handshake.key = makeKey(nil, &remoteKey)
		handshake.lineKey = makeKey(nil, &remoteLineKey)
		handshake.parts = parts
	}

	{ // make macKey
		box.Precompute(&macKey, &remoteKey, cs3aLocalKey.prv)

		var (
			sha = sha256.New()
		)

		sha.Write(p[lenKey : lenKey+lenNonce])
		sha.Write(macKey[:])
		sha.Sum(macKey[:0])
	}

	if !poly1305.Verify(&mac, p[:lenKey+lenNonce+ctLen], &macKey) {
		return nil, cipherset.ErrInvalidMessage
	}

	return handshake, nil
}

type state struct {
	mtx               sync.RWMutex
	localKey          *key
	remoteKey         *key
	localLineKey      *key
	remoteLineKey     *key
	localToken        *cipherset.Token
	remoteToken       *cipherset.Token
	macKeyBase        *[lenKey]byte
	lineEncryptionKey *[lenKey]byte
	lineDecryptionKey *[lenKey]byte
	nonce             *[lenNonce]byte
	pktNoncePrefix    *[16]byte
	pktNonceSuffix    uint64
}

func (*state) CSID() uint8 { return 0x3a }

func (s *state) IsHigh() bool {
	if s.localKey != nil && s.remoteKey != nil {
		return bytes.Compare((*s.remoteKey.pub)[:], (*s.localKey.pub)[:]) < 0
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

	if s.nonce == nil {
		s.nonce = new([lenNonce]byte)
		io.ReadFull(rand.Reader, s.nonce[:])
	}

	if s.pktNoncePrefix == nil {
		s.pktNoncePrefix = new([16]byte)
		io.ReadFull(rand.Reader, s.pktNoncePrefix[:])
	}

	// generate a local line Key
	if s.localLineKey == nil {
		s.localLineKey, _ = generateKey()
	}

	// generate mac key base
	if s.macKeyBase == nil && s.localKey.CanSign() && s.remoteKey.CanEncrypt() {
		s.macKeyBase = new([lenKey]byte)
		box.Precompute(s.macKeyBase, s.remoteKey.pub, s.localKey.prv)
	}

	// make local token
	if s.localToken == nil && s.localLineKey != nil {
		s.localToken = new(cipherset.Token)
		sha := sha256.Sum256((*s.localLineKey.pub)[:lenToken])
		copy((*s.localToken)[:], sha[:lenToken])
	}

	// make remote token
	if s.remoteToken == nil && s.remoteLineKey != nil {
		s.remoteToken = new(cipherset.Token)
		sha := sha256.Sum256((*s.remoteLineKey.pub)[:lenToken])
		copy((*s.remoteToken)[:], sha[:lenToken])
	}

	// generate line keys
	if s.localToken != nil && s.remoteToken != nil &&
		(s.lineEncryptionKey == nil || s.lineDecryptionKey == nil) {
		var sharedKey [lenKey]byte
		box.Precompute(&sharedKey, s.remoteLineKey.pub, s.localLineKey.prv)

		sha := sha256.New()
		s.lineEncryptionKey = new([lenKey]byte)
		sha.Write(sharedKey[:])
		sha.Write(s.localLineKey.pub[:])
		sha.Write(s.remoteLineKey.pub[:])
		sha.Sum((*s.lineEncryptionKey)[:0])

		sha.Reset()
		s.lineDecryptionKey = new([lenKey]byte)
		sha.Write(sharedKey[:])
		sha.Write(s.remoteLineKey.pub[:])
		sha.Write(s.localLineKey.pub[:])
		sha.Sum((*s.lineDecryptionKey)[:0])
	}
}

func (s *state) macKey(seq []byte) *[32]byte {
	if len(seq) != lenNonce {
		return nil
	}

	if s.macKeyBase == nil {
		return nil
	}

	var (
		macKey = new([lenKey]byte)
		sha    = sha256.New()
	)
	sha.Write(seq)
	sha.Write((*s.macKeyBase)[:])
	sha.Sum((*macKey)[:0])
	return macKey
}

func (s *state) sign(sig, seq, p []byte) {
	if len(sig) != lenAuth {
		panic("invalid sig buffer len(sig) must be 16")
	}

	var (
		sum [lenAuth]byte
		key = s.macKey(seq)
	)

	if key == nil {
		panic("unable to generate a signature")
	}

	poly1305.Sum(&sum, p, key)
	copy(sig, sum[:])
}

func (s *state) verify(sig, seq, p []byte) bool {
	if len(sig) != lenAuth {
		return false
	}

	var (
		sum [lenAuth]byte
		key = s.macKey(seq)
	)

	if key == nil {
		return false
	}

	copy(sum[:], sig)
	return poly1305.Verify(&sum, p, key)
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
		out       = bufpool.GetBuffer()[:lenKey+lenNonce+len(in)+box.Overhead+lenAuth]
		agreedKey [lenKey]byte
		ctLen     int
	)

	if !s.CanEncryptMessage() {
		panic("unable to encrypt message")
	}

	// copy public senderLineKey
	copy(out[:lenKey], (*s.localLineKey.pub)[:])

	// copy the nonce
	copy(out[lenKey:lenKey+lenNonce], s.nonce[:lenNonce])

	// make the agreedKey
	box.Precompute(&agreedKey, s.remoteKey.pub, s.localLineKey.prv)

	// encrypt p
	ctLen = len(box.SealAfterPrecomputation(out[lenKey+lenNonce:lenKey+lenNonce], in, s.nonce, &agreedKey))

	// Sign message
	s.sign(out[lenKey+lenNonce+ctLen:], s.nonce[:lenNonce], out[:lenKey+lenNonce+ctLen])

	return out[:lenKey+lenNonce+ctLen+lenAuth], nil
}

func (s *state) EncryptHandshake(at uint32, compact cipherset.Parts) ([]byte, error) {
	pkt := &lob.Packet{Body: s.localKey.Public()}
	compact.ApplyToHeader(pkt.Header())
	pkt.Header().SetUint32("at", at)
	data, err := lob.Encode(pkt)
	if err != nil {
		return nil, err
	}
	return s.EncryptMessage(data)
}

func (s *state) ApplyHandshake(h cipherset.Handshake) bool {
	var (
		hs, _ = h.(*handshake)
	)

	if hs == nil {
		return false
	}

	if s.remoteKey != nil && *s.remoteKey.pub != *hs.key.pub {
		return false
	}

	if s.remoteLineKey != nil && *s.remoteLineKey.pub != *hs.lineKey.pub {
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
		inner []byte
		body  []byte
		nonce [lenNonce]byte
		ctLen int
		err   error
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

	// make nonce
	copy(nonce[:], s.pktNoncePrefix[:])
	nonceSuffix := atomic.AddUint64(&s.pktNonceSuffix, 1)
	binary.BigEndian.PutUint64(nonce[16:], nonceSuffix)

	// alloc enough space
	body = bufpool.GetBuffer()[:lenToken+lenNonce+len(inner)+box.Overhead]

	// copy token
	copy(body[:lenToken], (*s.remoteToken)[:])

	// copy nonce
	copy(body[lenToken:lenToken+lenNonce], nonce[:])

	// encrypt inner packet
	ctLen = len(box.SealAfterPrecomputation(body[lenToken+lenNonce:lenToken+lenNonce], inner, &nonce, s.lineEncryptionKey))
	body = body[:lenToken+lenNonce+ctLen]

	bufpool.PutBuffer(inner)

	return &lob.Packet{Body: body}, nil
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

	if len(pkt.Head) != 0 || !pkt.Header().IsZero() || len(pkt.Body) < lenToken+lenNonce {
		return nil, cipherset.ErrInvalidPacket
	}

	var (
		nonce [lenNonce]byte
		inner = bufpool.GetBuffer()
		ok    bool
	)

	// compare token
	if !bytes.Equal(pkt.Body[:lenToken], (*s.localToken)[:]) {
		return nil, cipherset.ErrInvalidPacket
	}

	// copy nonce
	copy(nonce[:], pkt.Body[lenToken:lenToken+lenNonce])

	// decrypt inner packet
	inner, ok = box.OpenAfterPrecomputation(inner[:0], pkt.Body[lenToken+lenNonce:], &nonce, s.lineDecryptionKey)
	if !ok {
		return nil, cipherset.ErrInvalidPacket
	}

	return lob.Decode(inner)
}

type key struct {
	pub *[32]byte
	prv *[32]byte
}

func makeKey(prv, pub *[lenKey]byte) *key {
	if prv != nil {
		prvCopy := new([lenKey]byte)
		copy((*prvCopy)[:], (*prv)[:])
		prv = prvCopy
	}

	if pub != nil {
		pubCopy := new([lenKey]byte)
		copy((*pubCopy)[:], (*pub)[:])
		pub = pubCopy
	}

	return &key{pub: pub, prv: prv}
}

func generateKey() (*key, error) {
	pub, prv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return makeKey(prv, pub), nil
}

func (k *key) CSID() uint8 { return 0x3a }

func (k *key) Public() []byte {
	if k == nil || k.pub == nil {
		return nil
	}

	buf := make([]byte, lenKey)
	copy(buf, (*k.pub)[:])
	return buf
}

func (k *key) Private() []byte {
	if k == nil || k.prv == nil {
		return nil
	}

	buf := make([]byte, lenKey)
	copy(buf, (*k.prv)[:])
	return buf
}

func (k *key) String() string {
	return base32util.EncodeToString((*k.pub)[:])
}

func (k *key) CanSign() bool {
	return k != nil && k.prv != nil
}

func (k *key) CanEncrypt() bool {
	return k != nil && k.pub != nil
}

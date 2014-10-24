// Cipher Set 1a implementation.
package cs1a

import (
	"bytes"
	"crypto/aes"
	Cipher "crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a/eccp"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a/ecdh"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs1a/secp160r1"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/util/bufpool"
)

var (
	_ cipherset.Cipher    = (*cipher)(nil)
	_ cipherset.State     = (*state)(nil)
	_ cipherset.Key       = (*key)(nil)
	_ cipherset.Handshake = (*handshake)(nil)
)

func init() {
	cipherset.Register(0x1a, &cipher{})
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

func (h *handshake) At() uint32  { return h.at }
func (k *handshake) CSID() uint8 { return 0x1a }
func (k *cipher) CSID() uint8    { return 0x1a }

func (c *cipher) DecodeKey(pub, prv string) (cipherset.Key, error) {
	return decodeKey(pub, prv)
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
	if len(p) < 21+4+4 {
		return nil, cipherset.ErrInvalidMessage
	}

	var (
		ctLen         = len(p) - (21 + 4 + 4)
		out           = make([]byte, ctLen)
		localKey_, _  = localKey.(*key)
		remoteKey_, _ = remoteKey.(*key)
		remoteLineKey = p[:21]
		iv            = p[21 : 21+4]
		ciphertext    = p[21+4 : 21+4+ctLen]
		mac           = p[21+4+ctLen:]
	)

	if localKey_ == nil || remoteKey_ == nil {
		return nil, cipherset.ErrInvalidState
	}

	{ // verify mac
		macKey := ecdh.ComputeShared(secp160r1.P160(),
			remoteKey_.pub.x, remoteKey_.pub.y, localKey_.prv.d)
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

		shared := ecdh.ComputeShared(secp160r1.P160(), ephemX, ephemY, localKey_.prv.d)
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
		out               = make([]byte, ctLen)
		localKey_, _      = localKey.(*key)
		remoteKey         *key
		remoteLineKey     *key
		hshake            *handshake
		remoteLineKeyData = p[:21]
		iv                = p[21 : 21+4]
		ciphertext        = p[21+4 : 21+4+ctLen]
		mac               = p[21+4+ctLen:]
	)

	if localKey_ == nil {
		return nil, cipherset.ErrInvalidState
	}

	{ // descrypt inner
		ephemX, ephemY := eccp.Unmarshal(secp160r1.P160(), remoteLineKeyData)
		if ephemX == nil || ephemY == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		shared := ecdh.ComputeShared(secp160r1.P160(), ephemX, ephemY, localKey_.prv.d)
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

		delete(inner.Header(), "at")

		parts, err := cipherset.PartsFromHeader(inner.Header())
		if err != nil {
			return nil, cipherset.ErrInvalidMessage
		}

		if len(inner.Body) != 21 {
			return nil, cipherset.ErrInvalidMessage
		}

		remoteKey = &key{}
		remoteKey.pub.x, remoteKey.pub.y = eccp.Unmarshal(secp160r1.P160(), inner.Body)
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
			remoteKey.pub.x, remoteKey.pub.y, localKey_.prv.d)
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
	localKey          *key
	remoteKey         *key
	localLineKey      *key
	remoteLineKey     *key
	localToken        *cipherset.Token
	remoteToken       *cipherset.Token
	lineEncryptionKey []byte
	lineDecryptionKey []byte
}

func (k *state) CSID() uint8 { return 0x1a }

func (s *state) IsHigh() bool {
	if s.localKey != nil && s.remoteKey != nil {
		return s.localKey.pub.x.Cmp(s.remoteKey.pub.x) > 0
	}
	return false
}

func (s *state) SenderToken() cipherset.Token {
	if s.localToken != nil {
		return *s.localToken
	}
	return cipherset.ZeroToken
}

func (s *state) ReceiverToken() cipherset.Token {
	if s.remoteToken != nil {
		return *s.remoteToken
	}
	return cipherset.ZeroToken
}

func (s *state) SetRemoteKey(remoteKey cipherset.Key) error {
	if k, ok := remoteKey.(*key); ok && k != nil && k.CanEncrypt() {
		s.remoteKey = k
		s.update()
		return nil
	}
	return cipherset.ErrInvalidKey
}

func (s *state) setRemoteLineKey(k *key) {
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
	if s.localToken != nil && s.remoteToken != nil {
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
	return s.lineEncryptionKey != nil
}

func (s *state) CanDecryptMessage() bool {
	return s.localKey != nil && s.remoteKey != nil && s.localLineKey != nil
}

func (s *state) CanDecryptHandshake() bool {
	return s.localKey != nil && s.localLineKey != nil
}

func (s *state) CanDecryptPacket() bool {
	return s.lineDecryptionKey != nil
}

func (s *state) EncryptMessage(in []byte) ([]byte, error) {
	var (
		ctLen = len(in)
		out   = bufpool.GetBuffer()[:21+4+ctLen+4]
	)

	if !s.CanEncryptMessage() {
		panic("unable to encrypt message")
	}

	// copy public senderLineKey
	copy(out[:21], s.localLineKey.Public())

	// copy the nonce
	_, err := io.ReadFull(rand.Reader, out[21:21+4])
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
		copy(aesIv[:], out[21:21+4])

		aes := Cipher.NewCTR(aesBlock, aesIv[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aes.XORKeyStream(out[21+4:21+4+ctLen], in)
	}

	{ // compute HMAC
		macKey := ecdh.ComputeShared(secp160r1.P160(),
			s.remoteKey.pub.x, s.remoteKey.pub.y, s.localKey.prv.d)
		macKey = append(macKey, out[21:21+4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(out[:21+4+ctLen])
		sum := h.Sum(nil)
		copy(out[21+4+ctLen:], fold(sum, 4))
	}

	out = out[:21+4+ctLen+4]

	return out, nil
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

	if s.remoteLineKey != nil && !bytes.Equal(s.remoteLineKey.Public(), hs.lineKey.Public()) {
		return false
	}

	if s.remoteKey != nil && !bytes.Equal(s.remoteKey.Public(), hs.key.Public()) {
		return false
	}

	s.setRemoteLineKey(hs.lineKey)
	s.SetRemoteKey(hs.key)
	return true
}

func (s *state) EncryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	var (
		inner []byte
		body  []byte
		nonce [16]byte
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

	ctLen = len(inner)

	// make nonce
	_, err = io.ReadFull(rand.Reader, nonce[:4])
	if err != nil {
		return nil, err
	}

	// alloc enough space
	body = bufpool.GetBuffer()[:16+4+len(inner)+4]

	// copy token
	copy(body[:16], (*s.localToken)[:])

	// copy nonce
	copy(body[16:16+4], nonce[:])

	{ // encrypt inner
		aesBlock, err := aes.NewCipher(s.lineEncryptionKey)
		if err != nil {
			return nil, err
		}

		aes := Cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidMessage
		}

		aes.XORKeyStream(body[16+4:16+4+ctLen], inner)
	}

	{ // compute HMAC
		macKey := append(s.lineEncryptionKey, body[16:16+4]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(body[:16+4+ctLen])
		sum := h.Sum(nil)
		copy(body[16+4+ctLen:], fold(sum, 4))
	}

	return &lob.Packet{Body: body}, nil
}

func (s *state) DecryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	if !s.CanDecryptPacket() {
		return nil, cipherset.ErrInvalidState
	}
	if pkt == nil {
		return nil, nil
	}

	if len(pkt.Head) != 0 || len(pkt.Header()) != 0 || len(pkt.Body) < 16+4+4 {
		return nil, cipherset.ErrInvalidPacket
	}

	var (
		nonce    [16]byte
		innerLen = len(pkt.Body) - (16 + 4 + 4)
		inner    = make([]byte, innerLen)
	)

	// compare token
	if !bytes.Equal(pkt.Body[:16], (*s.remoteToken)[:]) {
		return nil, cipherset.ErrInvalidPacket
	}

	// copy nonce
	copy(nonce[:], pkt.Body[16:16+4])

	{ // verify hmac
		mac := pkt.Body[16+4+innerLen:]

		macKey := append(s.lineDecryptionKey, nonce[:]...)

		h := hmac.New(sha256.New, macKey)
		h.Write(pkt.Body[:16+4+innerLen])
		if subtle.ConstantTimeCompare(mac, fold(h.Sum(nil), 4)) != 1 {
			return nil, cipherset.ErrInvalidPacket
		}
	}

	{ // decrypt inner
		aesBlock, err := aes.NewCipher(s.lineDecryptionKey)
		if err != nil {
			return nil, err
		}

		aes := Cipher.NewCTR(aesBlock, nonce[:])
		if aes == nil {
			return nil, cipherset.ErrInvalidPacket
		}

		aes.XORKeyStream(inner, pkt.Body[16+4:16+4+innerLen])
	}

	return lob.Decode(inner)
}

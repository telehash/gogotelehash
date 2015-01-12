package cipherset

import (
	"bytes"
	"sync"

	"github.com/telehash/gogotelehash/e3x/cipherset/driver"
	"github.com/telehash/gogotelehash/internal/lob"
)

var (
	ErrUnknownCSID    = driver.ErrUnknownCSID
	ErrInvalidKey     = driver.ErrInvalidKey
	ErrInvalidState   = driver.ErrInvalidState
	ErrInvalidMessage = driver.ErrInvalidMessage
	ErrInvalidPacket  = driver.ErrInvalidPacket

	ErrSessionReset = driver.ErrSessionReset
)

// Self represents the the local identity
type Self struct {
	keys    map[uint8]*PrivateKey
	pubKeys map[uint8][]byte
	drivers map[uint8]driver.Self
}

// Session represents the cryptographic state between two endpoints
type Session struct {
	mtx    sync.RWMutex
	csid   uint8
	isHigh bool
	driver driver.Session
}

// PrivateKey is a private key (accompanied by its public key) in binary format.
type PrivateKey struct {
	Private []byte
	Public  []byte
}

func GenerateKey(csid uint8) (*PrivateKey, error) {
	drv := driver.Lookup(csid)
	if drv == nil {
		return nil, ErrUnknownCSID
	}

	prv, pub, err := drv.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{prv, pub}, nil
}

func GenerateKeys(csids ...uint8) (map[uint8]*PrivateKey, error) {
	if len(csids) == 0 {
		csids = driver.AvailableCSIDs()
	}

	keys := make(map[uint8]*PrivateKey, len(csids))
	for _, csid := range csids {
		key, err := GenerateKey(csid)
		if err != nil {
			return nil, err
		}
		keys[csid] = key
	}

	return keys, nil
}

// New makes a new Self with the provided keys
func New(keys map[uint8]*PrivateKey) (*Self, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidState
	}

	self := &Self{}
	self.keys = keys
	self.pubKeys = make(map[uint8][]byte, len(keys))
	self.drivers = make(map[uint8]driver.Self, len(keys))

	for csid, key := range keys {
		drv := driver.Lookup(csid)
		if drv == nil {
			return nil, ErrUnknownCSID
		}

		s, err := drv.NewSelf(key.Private, key.Public)
		if err != nil {
			return nil, err
		}

		self.pubKeys[csid] = key.Public
		self.drivers[csid] = s
	}

	return self, nil
}

func (s *Self) PublicKeys() map[uint8][]byte {
	return s.pubKeys
}

// DecryptMessage decrypts a message packet.
//
// DecryptMessage does not verify messages. VerifyMessage must be used
// to verify them.
func (s *Self) DecryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	if pkt == nil {
		return nil, ErrInvalidMessage
	}

	hdr := pkt.Header()
	if !hdr.IsBinary() || len(hdr.Bytes) != 1 {
		return nil, ErrInvalidMessage
	}

	csid := hdr.Bytes[0]
	drv := s.drivers[csid]
	if drv == nil {
		return nil, ErrUnknownCSID
	}

	return drv.DecryptMessage(pkt)
}

// NewSession makes a new session with the provided public keys.
func (s *Self) NewSession(keys map[uint8][]byte) (*Session, error) {
	var (
		selectedCSID  uint8
		selectedKey   []byte
		selfDriver    driver.Self
		sessionDriver driver.Session
		session       *Session
		err           error
	)

	for csid, key := range keys {
		if csid <= selectedCSID {
			// skip we already selected a better CSID
			continue
		}

		drv := s.drivers[csid]
		if drv == nil {
			// skip; we don't support this CSID
			continue
		}

		selectedCSID = csid
		selectedKey = key
		selfDriver = drv
	}

	if selfDriver == nil {
		return nil, ErrUnknownCSID
	}

	sessionDriver, err = selfDriver.NewSession(keys[selectedCSID])
	if err != nil {
		return nil, err
	}

	session = &Session{
		csid:   selectedCSID,
		driver: sessionDriver,
		isHigh: bytes.Compare(selectedKey, s.keys[selectedCSID].Public) < 0,
	}

	return session, nil
}

func (s *Session) CSID() uint8 {
	return s.csid
}

func (s *Session) IsHigh() bool {
	return s.isHigh
}

func (s *Session) LocalToken() Token {
	s.mtx.RLock()
	token := Token(s.driver.LocalToken())
	s.mtx.RUnlock()
	return token
}

func (s *Session) RemoteToken() Token {
	s.mtx.RLock()
	token := Token(s.driver.RemoteToken())
	s.mtx.RUnlock()
	return token
}

func (s *Session) NegotiatedEphemeralKeys() bool {
	s.mtx.RLock()
	ok := s.driver.NegotiatedEphemeralKeys()
	s.mtx.RUnlock()
	return ok
}

// VerifyMessage verifies the message. pkt is the outer packet.
//
// VerifyMessage must return ErrSessionReset when the remote ephemeral key
// doesn't match the one previously seen.
func (s *Session) VerifyMessage(pkt *lob.Packet) error {
	var (
		done bool
		err  error
	)

	s.mtx.RLock()
	if s.driver.NegotiatedEphemeralKeys() {
		done = true
		err = s.driver.VerifyMessage(pkt)
	}
	s.mtx.RUnlock()

	if !done {
		s.mtx.Lock()
		err = s.driver.VerifyMessage(pkt)
		s.mtx.Unlock()
	}

	return err
}

// EncryptMessage encrypts and signs a message packet.
func (s *Session) EncryptMessage(pkt *lob.Packet) (*lob.Packet, error) {
	s.mtx.RLock()
	pkt, err := s.driver.EncryptMessage(pkt)
	s.mtx.RUnlock()
	return pkt, err
}

// EncryptPacket encrypts and signs a channel packet.
func (s *Session) EncryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	s.mtx.RLock()
	pkt, err := s.driver.EncryptPacket(pkt)
	s.mtx.RUnlock()
	return pkt, err
}

// DecryptPacket decrypts and verifies a channel packet.
func (s *Session) DecryptPacket(pkt *lob.Packet) (*lob.Packet, error) {
	s.mtx.RLock()
	pkt, err := s.driver.DecryptPacket(pkt)
	s.mtx.RUnlock()
	return pkt, err
}

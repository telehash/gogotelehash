package cipherset

import (
	"github.com/telehash/gogotelehash/util/base32util"
)

var ciphers = map[uint8]Cipher{}

func Register(csid uint8, c Cipher) {
	if ciphers[csid] != nil {
		panic("CSID is already registered")
	}
	if c == nil {
		panic("cipher must no  be nil")
	}
	ciphers[csid] = c
}

func GenerateKey(csid uint8) (Key, error) {
	c := ciphers[csid]
	if c == nil {
		return nil, ErrUnknownCSID
	}

	return c.GenerateKey()
}

func DecodeKey(csid uint8, pub, prv string) (Key, error) {
	c := ciphers[csid]

	if c == nil {
		pubKey, err := base32util.DecodeString(pub)
		if err != nil {
			return nil, ErrInvalidKey
		}
		prvKey, err := base32util.DecodeString(prv)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return opaqueKey{csid, pubKey, prvKey}, nil
	}

	return c.DecodeKey(pub, prv)
}

func DecryptMessage(csid uint8, localKey, remoteKey Key, p []byte) ([]byte, error) {
	c := ciphers[csid]
	if c == nil {
		return nil, ErrUnknownCSID
	}

	return c.DecryptMessage(localKey, remoteKey, p)
}

func DecryptHandshake(csid uint8, localKey Key, p []byte) (Handshake, error) {
	c := ciphers[csid]
	if c == nil {
		return nil, ErrUnknownCSID
	}

	return c.DecryptHandshake(localKey, p)
}

func NewState(csid uint8, localKey Key) (State, error) {
	c := ciphers[csid]
	if c == nil {
		return nil, ErrUnknownCSID
	}

	return c.NewState(localKey)
}

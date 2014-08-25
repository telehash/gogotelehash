package cipherset

import (
	"bitbucket.org/simonmenke/go-telehash/base32"
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

func DecodeKey(csid uint8, s string) (Key, error) {
	c := ciphers[csid]
	if c == nil {
		key, err := base32.DecodeString(s)
		if err != nil {
			return nil, ErrInvalidKey
		}
		return opaqueKey(key), nil
	}

	return c.DecodeKey(s)
}

func NewState(csid uint8, localKey Key, isSender bool) (State, error) {
	c := ciphers[csid]
	if c == nil {
		return nil, ErrUnknownCSID
	}

	return c.NewState(localKey, isSender)
}

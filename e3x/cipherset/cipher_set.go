package cipherset

import (
	"errors"

	"bitbucket.org/simonmenke/go-telehash/lob"
)

var (
	ErrInvalidKey     = errors.New("cipherset: invalid key")
	ErrInvalidState   = errors.New("cipherset: invalid state")
	ErrInvalidMessage = errors.New("cipherset: invalid message")
	ErrInvalidPacket  = errors.New("cipherset: invalid packet")
)

type Cipher interface {
	GenerateKey() (Key, error)
	NewState(localKey Key, isSender bool) (State, error)
}

type State interface {
	SetRemoteKey(k Key) error

	NeedsRemoteKey() bool
	CanEncryptMessage() bool
	CanEncryptHandshake() bool
	CanEncryptPacket() bool
	CanDecryptMessage() bool
	CanDecryptHandshake() bool
	CanDecryptPacket() bool

	RemoteToken() Token

	EncryptMessage(seq uint32, in []byte) ([]byte, error)
	DecryptMessage(p []byte) (uint32, []byte, error)

	EncryptHandshake(seq uint32, compact map[string]string) ([]byte, error)
	DecryptHandshake(p []byte) (uint32, Key, map[string]string, error)

	EncryptPacket(pkt *lob.Packet) (*lob.Packet, error)
	DecryptPacket(pkt *lob.Packet) (*lob.Packet, error)
}

type Key interface {
	Bytes() []byte
	CanSign() bool
	CanEncrypt() bool
}

type Token [16]byte

var ZeroToken Token

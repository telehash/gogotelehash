package cipherset

import (
	"errors"

	"bitbucket.org/simonmenke/go-telehash/lob"
)

var (
	ErrUnknownCSID    = errors.New("cipherset: unknown CSID")
	ErrInvalidKey     = errors.New("cipherset: invalid key")
	ErrInvalidState   = errors.New("cipherset: invalid state")
	ErrInvalidMessage = errors.New("cipherset: invalid message")
	ErrInvalidPacket  = errors.New("cipherset: invalid packet")
)

type Cipher interface {
	CSID() uint8

	DecodeKey(pub, prv string) (Key, error)
	GenerateKey() (Key, error)

	DecryptMessage(localKey, remoteKey Key, p []byte) ([]byte, error)
	DecryptHandshake(localKey Key, p []byte) (uint32, Handshake, error)

	NewState(localKey Key) (State, error)
}

type State interface {
	CSID() uint8

	SetRemoteKey(k Key) error

	NeedsRemoteKey() bool
	CanEncryptMessage() bool
	CanEncryptHandshake() bool
	CanEncryptPacket() bool
	CanDecryptMessage() bool
	CanDecryptHandshake() bool
	CanDecryptPacket() bool

	IsHigh() bool
	RemoteToken() Token

	EncryptMessage(in []byte) ([]byte, error)
	EncryptHandshake(at uint32, compact Parts) ([]byte, error)
	ApplyHandshake(Handshake) bool

	EncryptPacket(pkt *lob.Packet) (*lob.Packet, error)
	DecryptPacket(pkt *lob.Packet) (*lob.Packet, error)
}

type Handshake interface {
	CSID() uint8

	At() uint32
	Token() Token
	PublicKey() Key // The sender public key
	Parts() Parts   // The sender parts
}

type Key interface {
	CSID() uint8

	String() string
	Public() []byte
	Private() []byte
	CanSign() bool
	CanEncrypt() bool
}

type Token [16]byte

var ZeroToken Token

func ExtractToken(msg []byte) Token {
	l := len(msg)
	if l < 3 {
		return ZeroToken
	}

	if msg[0] == 0 && msg[1] == 1 && len(msg) >= 3+16 {
		var token Token
		copy(token[:], msg[:3:3+16])
		return token
	}

	if msg[0] == 0 && msg[1] == 0 && len(msg) >= 2+16 {
		var token Token
		copy(token[:], msg[:2:2+16])
		return token
	}

	return ZeroToken
}

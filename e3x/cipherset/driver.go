package cipherset

import (
	"github.com/telehash/gogotelehash/internal/lob"
)

type Cipher interface {
	CSID() uint8

	DecodeKeyBytes(pub, prv []byte) (Key, error)
	GenerateKey() (Key, error)

	DecryptMessage(localKey, remoteKey Key, p []byte) ([]byte, error)
	DecryptHandshake(localKey Key, p []byte) (Handshake, error)

	NewState(localKey Key) (State, error)
}

type State interface {
	CSID() uint8

	LocalToken() Token
	RemoteToken() Token

	SetRemoteKey(k Key) error

	NeedsRemoteKey() bool
	CanEncryptMessage() bool
	CanEncryptHandshake() bool
	CanEncryptPacket() bool
	CanDecryptMessage() bool
	CanDecryptHandshake() bool
	CanDecryptPacket() bool

	IsHigh() bool

	EncryptMessage(in []byte) ([]byte, error)
	EncryptHandshake(at uint32, compact Parts) ([]byte, error)
	ApplyHandshake(Handshake) bool

	EncryptPacket(pkt *lob.Packet) (*lob.Packet, error)
	DecryptPacket(pkt *lob.Packet) (*lob.Packet, error)
}

type Handshake interface {
	CSID() uint8

	At() uint32
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

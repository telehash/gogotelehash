package cipherset

import (
	"errors"
)

var (
	ErrInvalidSenderKey     = errors.New("cipherset: invalid sender key")
	ErrInvalidReceiverKey   = errors.New("cipherset: invalid receiver key")
	ErrInvalidMac           = errors.New("cipherset: invalid mac")
	ErrInvalidBody          = errors.New("cipherset: invalid body")
	ErrNotEnoughBufferSpace = errors.New("cipherset: not enough buffer space")
)

type Cipher interface {
	GenerateKey() (Key, error)

	MakeSession(localKey Key, remoteKey Key) (Session, error)

	MessageOverhead() int
	EncryptMessage(receiverKey, senderKey, senderLineKey Key, seq uint32, in, buf []byte) ([]byte, error)
	DecryptMessage(receiverKey, senderKey Key, p []byte) (uint32, []byte, error)

	EncryptHandshake(receiverKey, senderKey, senderLineKey Key, seq uint32, buf []byte) ([]byte, error)
	DecryptHandshake(receiverKey Key, p []byte) (uint32, Key, error)
}

type Session interface {
	Encrypt(p []byte) ([]byte, error)
	Decrypt(p []byte) ([]byte, error)
}

type Key interface {
	Bytes() []byte
	CanSign() bool
	CanEncrypt() bool
}

package telehash

import (
	"github.com/gokyle/ecdh"
)

type Line struct {
	_switch      *Switch
	LineIn       []byte
	LineOut      []byte
	local_eckey  *ecdh.PrivateKey
	remote_eckey *ecdh.PublicKey
	enc_key      []byte
	dec_key      []byte
}

func (l *Line) can_activate() bool {
	return l.LineIn != nil && l.LineOut != nil && l.local_eckey != nil && l.remote_eckey != nil
}

func (l *Line) activate() error {
	sk, err := l.local_eckey.GenerateShared(l.remote_eckey, ecdh.MaxSharedKeyLength(l.remote_eckey))
	if err != nil {
		return err
	}

	l.enc_key = hash_SHA256(sk, l.LineOut, l.LineIn)
	l.dec_key = hash_SHA256(sk, l.LineIn, l.LineOut)

	return nil
}

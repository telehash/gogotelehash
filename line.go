package telehash

import (
	"encoding/hex"
	"github.com/gokyle/ecdh"
	"time"
)

type line_t struct {
	_switch      *Switch
	peer         *peer_t
	at           time.Time
	LineIn       []byte
	LineOut      []byte
	local_eckey  *ecdh.PrivateKey
	remote_eckey *ecdh.PublicKey
	enc_key      []byte
	dec_key      []byte
}

func (l *line_t) can_activate() bool {
	return l.LineIn != nil && l.LineOut != nil && l.local_eckey != nil && l.remote_eckey != nil
}

func (l *line_t) activate() error {
	sk, err := l.local_eckey.GenerateShared(l.remote_eckey, ecdh.MaxSharedKeyLength(l.remote_eckey))
	if err != nil {
		return err
	}

	l.enc_key = hash_SHA256(sk, l.LineOut, l.LineIn)
	l.dec_key = hash_SHA256(sk, l.LineIn, l.LineOut)

	delete(l._switch.o_open, l.peer.hashname)
	delete(l._switch.i_open, l.peer.hashname)
	l._switch.lines[hex.EncodeToString(l.LineOut)] = l
	l.peer.set_line(l)

	Log.Debugf("line opened: %s -> %s", l._switch.hashname, l.peer.hashname)

	return nil
}

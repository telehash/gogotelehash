package cipherset

import (
	"crypto/sha256"
	"fmt"
)

type Token [16]byte

var ZeroToken Token

func ExtractToken(msg []byte) Token {
	var (
		token Token
		l     = len(msg)
	)

	if l >= 3+16 && msg[0] == 0 && msg[1] == 1 {
		// for messages
		sha := sha256.Sum256(msg[3 : 3+16])
		copy(token[:], sha[:16])

	} else if l >= 2+16 && msg[0] == 0 && msg[1] == 0 {
		// for channel packets
		copy(token[:], msg[2:2+16])

	} else {
		// everything else
		return ZeroToken

	}

	return token
}

func (t Token) String() string {
	return fmt.Sprintf("%x", t[:])
}

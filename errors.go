package telehash

import (
	"errors"
)

var (
	ErrUDPConnClosed   = errors.New("upd: connection closed")
	ErrInvalidHashname = errors.New("telehash: invalid hashname")
	ErrTimeout         = errors.New("telehash: timeout")

	errMissingPublicKey = errors.New("line: missing public key")
)

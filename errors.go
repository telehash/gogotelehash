package telehash

import (
	"errors"
)

var (
	ErrUDPConnClosed   = errors.New("upd: connection closed")
	ErrInvalidHashname = errors.New("telehash: invalid hashname")

	errMissingPublicKey = errors.New("line: missing public key")
)

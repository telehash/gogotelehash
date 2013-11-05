package telehash

import (
	"errors"
)

var (
	ErrUDPConnClosed = errors.New("upd: connection closed")

	errMissingPublicKey = errors.New("line: missing public key")
)

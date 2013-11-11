package telehash

import (
	"errors"
)

var (
	ErrUDPConnClosed   = errors.New("upd: connection closed")
	ErrInvalidHashname = errors.New("telehash: invalid hashname")
	ErrTimeout         = errors.New("telehash: timeout")

	errInvalidOpenReq   = errors.New("line: invalid open request")
	errMissingPublicKey = errors.New("line: missing public key")
	errEmptyPkt         = errors.New("net: empty packet")
	errInvalidPkt       = errors.New("net: invalid packet")
	errUnknownLine      = errors.New("net: unknown line")
	errUnknownChannel   = errors.New("net: unknown channel")
)

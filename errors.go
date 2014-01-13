package telehash

import (
	"errors"
)

var (
	ErrUDPConnClosed          = errors.New("upd: connection closed")
	ErrInvalidHashname        = errors.New("telehash: invalid hashname")
	ErrTimeout                = errors.New("telehash: timeout")
	ErrChannelBroken          = errors.New("telehash: broken channel")
	ErrPeerBroken             = errors.New("telehash: broken peer")
	ErrUnknownPeer            = errors.New("telehash: unknown peer")
	ErrSendOnClosedChannel    = errors.New("telehash: send on closed channel")
	ErrReceiveOnClosedChannel = errors.New("telehash: receive on closed channel")
	ErrInvalidNetwork         = errors.New("telehash: invalid network")
	ErrSwitchAlreadyRunning   = errors.New("telehash: switch is already running")

	errInvalidOpenReq   = errors.New("line: invalid open request")
	errMissingPublicKey = errors.New("line: missing public key")
	errEmptyPkt         = errors.New("net: empty packet")
	errInvalidPkt       = errors.New("net: invalid packet")
	errUnknownLine      = errors.New("net: unknown line")
	errUnknownChannel   = errors.New("net: unknown channel")
	errNoOpenLine       = errors.New("peer: no open line")
	errDuplicatePacket  = errors.New("channel: duplicate packet")
)

package cipherset

import (
	"errors"
)

type CSID uint8

var (
	ErrInvalidCSID = errors.New("invalid CSID")
)

func ExtractCSID(msg []byte) CSID {
	var (
		csid CSID
		l    = len(msg)
	)

	if l >= 3 && msg[0] == 0 && msg[1] == 1 {
		csid = CSID(msg[2])
	}

	return csid
}

func (id CSID) MarshalText() (text []byte, err error) {
	b := make([]byte, 2)
	b[0] = toHalfHex(uint8(id) >> 4)
	b[1] = toHalfHex(uint8(id))
	return b, nil
}

func (idPtr *CSID) UnmarshalText(text []byte) error {
	if len(text) != 2 {
		return ErrInvalidCSID
	}

	upper, ok1 := fromHalfHex(text[0])
	lower, ok2 := fromHalfHex(text[1])
	if !ok1 || !ok2 {
		return ErrInvalidCSID
	}

	*idPtr = CSID((upper << 4) | lower)
	return nil
}

func toHalfHex(b uint8) byte {
	b = b & 0x0F

	if b < 10 {
		return '0' + byte(b)
	}

	return 'a' + byte(b-10)
}

func fromHalfHex(b byte) (uint8, bool) {
	if '0' <= b && b <= '9' {
		return uint8(b - '0'), true
	}
	if 'a' <= b && b <= 'f' {
		return uint8(b - 'a'), true
	}
	if 'A' <= b && b <= 'F' {
		return uint8(b - 'A'), true
	}
	return 0, false
}

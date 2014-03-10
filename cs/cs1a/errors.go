package cs1a

import (
	"fmt"
)

type InvalidPacketError struct {
	Reason error
}

func (err *InvalidPacketError) Error() string {
	if err.Reason != nil {
		return fmt.Sprintf("cs1a: invalid packet (reason: %s)", err.Reason)
	}
	return fmt.Sprintf("cs1a: invalid packet")
}

type EncodePacketError struct {
	Reason error
}

func (err *EncodePacketError) Error() string {
	if err.Reason != nil {
		return fmt.Sprintf("cs1a: failed to encode packet (reason: %s)", err.Reason)
	}
	return fmt.Sprintf("cs1a: failed to encode packet")
}

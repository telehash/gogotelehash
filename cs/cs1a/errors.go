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

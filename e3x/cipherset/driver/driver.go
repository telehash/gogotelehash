package driver

import (
	"errors"
	"fmt"

	"github.com/telehash/gogotelehash/internal/lob"
)

var (
	ErrUnknownCSID    = errors.New("cipherset: unknown CSID")
	ErrInvalidKey     = errors.New("cipherset: invalid key")
	ErrInvalidState   = errors.New("cipherset: invalid state")
	ErrInvalidMessage = errors.New("cipherset: invalid message")
	ErrInvalidPacket  = errors.New("cipherset: invalid packet")

	ErrSessionReset = errors.New("ciperset: session reset")
)

type Driver interface {
	CSID() uint8
	GenerateKey() (prv, pub []byte, err error)
	NewSelf(prv, pub []byte) (Self, error)
}

type Self interface {
	// DecryptMessage decrypts a message packet.
	//
	// DecryptMessage does not verify messages. VerifyMessage must be used
	// to verify them.
	DecryptMessage(pkt *lob.Packet) (*lob.Packet, error)

	// NewSession makes a new session with the provided public key.
	NewSession(key []byte) (Session, error)
}

type Session interface {
	LocalToken() [16]byte
	RemoteToken() [16]byte

	// NegotiatedEphemeralKeys should return true when the ephemeral keys are set.
	//
	// This is used as a hint to determine if exclusive access is required for
	// the next VerifyMessage call.
	NegotiatedEphemeralKeys() bool

	// VerifyMessage verifies the message. pkt is the outer packet.
	//
	// VerifyMessage will typically modify the remote ephemeral key
	// of the session whe the message is valid. When VerifyMessage is
	// called the driver is garanteed to have exclusive access to the
	// session state as long as NegotiatedEphemeralKeys() returns false.
	//
	// VerifyMessage must return ErrSessionReset when the remote ephemeral key
	// doesn't match the one previously seen.
	VerifyMessage(pkt *lob.Packet) error

	// EncryptMessage encrypts and signs a message packet.
	EncryptMessage(pkt *lob.Packet) (*lob.Packet, error)

	// EncryptPacket encrypts and signs a channel packet.
	EncryptPacket(pkt *lob.Packet) (*lob.Packet, error)

	// DecryptPacket decrypts and verifies a channel packet.
	DecryptPacket(pkt *lob.Packet) (*lob.Packet, error)
}

var drivers map[uint8]Driver

func Register(driver Driver) {
	if drivers == nil {
		drivers = make(map[uint8]Driver)
	}

	if driver == nil {
		panic("driver should not be nil")
	}

	if drivers[driver.CSID()] != nil {
		panic(fmt.Sprintf("driver for CSID %02x is already registerd", driver.CSID()))
	}

	drivers[driver.CSID()] = driver
}

func Lookup(csid uint8) Driver {
	if drivers == nil {
		return nil
	}

	return drivers[csid]
}

func AvailableCSIDs() []uint8 {
	csids := make([]uint8, 0, len(drivers))
	for csid := range drivers {
		csids = append(csids, csid)
	}
	return csids
}

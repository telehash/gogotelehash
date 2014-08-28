package nat

import (
	"errors"
	"math"
	"math/rand"
	"net"
	"time"
)

var ErrNoExternalAddress = errors.New("nat: no external address")
var ErrNoInternalAddress = errors.New("nat: no internal address")
var ErrNoNATFound = errors.New("nat: no NAT found")

// protocol is either "udp" or "tcp"
type NAT interface {
	Type() string
	GetDeviceAddress() (addr net.IP, err error)
	GetInternalAddress() (addr net.IP, err error)
	GetExternalAddress() (addr net.IP, err error)

	AddPortMapping(protocol string, internalPort int, description string, timeout time.Duration) (mappedExternalPort int, err error)
	DeletePortMapping(protocol string, internalPort int) (err error)
}

func Discover() (NAT, error) {
	select {
	case nat := <-discoverUPNP_IG1():
		return nat, nil
	case nat := <-discoverUPNP_IG2():
		return nat, nil
	case nat := <-discoverNATPMP():
		return nat, nil
	case <-time.After(10 * time.Second):
		return nil, ErrNoNATFound
	}
}

func randomPort() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(math.MaxUint16-10000) + 10000
}

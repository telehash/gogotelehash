package udp

import (
	"encoding/json"
	"net"

	"github.com/telehash/gogotelehash/transports"
)

func init() {
	transports.RegisterAddr(&udpv4{})
	transports.RegisterAddr(&udpv6{})
}

type udpAddr interface {
	net.Addr
	GetIP() net.IP
	GetPort() uint16
	ToUDPAddr() *net.UDPAddr
	IsIPv6() bool
}

type udpv4 net.UDPAddr
type udpv6 net.UDPAddr

func wrapAddr(addr *net.UDPAddr) udpAddr {
	if addr.IP.To4() == nil {
		return (*udpv6)(addr)
	}
	return (*udpv4)(addr)
}

func (u *udpv4) Network() string { return "udp4" }
func (u *udpv6) Network() string { return "udp6" }

func (u *udpv4) String() string { return u.ToUDPAddr().String() }
func (u *udpv6) String() string { return u.ToUDPAddr().String() }

func (u *udpv4) GetIP() net.IP { return u.ToUDPAddr().IP }
func (u *udpv6) GetIP() net.IP { return u.ToUDPAddr().IP }

func (u *udpv4) GetPort() uint16 { return uint16(u.ToUDPAddr().Port) }
func (u *udpv6) GetPort() uint16 { return uint16(u.ToUDPAddr().Port) }

func (u *udpv4) ToUDPAddr() *net.UDPAddr { return (*net.UDPAddr)(u) }
func (u *udpv6) ToUDPAddr() *net.UDPAddr { return (*net.UDPAddr)(u) }

func (u *udpv4) IsIPv6() bool { return false }
func (u *udpv6) IsIPv6() bool { return true }

func (u *udpv4) UnmarshalJSON(data []byte) error {
	var desc struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return transports.ErrInvalidAddr
	}

	ip := net.ParseIP(desc.IP)
	if ip == nil || ip.IsUnspecified() {
		return transports.ErrInvalidAddr
	}

	if desc.Port <= 0 || desc.Port >= 65535 {
		return transports.ErrInvalidAddr
	}

	addr := wrapAddr(&net.UDPAddr{IP: ip, Port: desc.Port})
	if addr.IsIPv6() {
		return transports.ErrInvalidAddr
	}

	*u = *(addr).(*udpv4)
	return nil
}

func (u *udpv6) UnmarshalJSON(data []byte) error {
	var desc struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return transports.ErrInvalidAddr
	}

	ip := net.ParseIP(desc.IP)
	if ip == nil || ip.IsUnspecified() {
		return transports.ErrInvalidAddr
	}

	if desc.Port <= 0 || desc.Port >= 65535 {
		return transports.ErrInvalidAddr
	}

	addr := wrapAddr(&net.UDPAddr{IP: ip, Port: desc.Port})
	if addr.IsIPv6() {
		return transports.ErrInvalidAddr
	}

	*u = *addr.(*udpv6)
	return nil
}

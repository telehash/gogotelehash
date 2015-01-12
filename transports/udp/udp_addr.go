package udp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/dgram"
	"github.com/telehash/gogotelehash/transports/nat"
)

func init() {
	transports.RegisterAddr(&udpv4{})
	transports.RegisterAddr(&udpv6{})

	transports.RegisterResolver("udp4", func(str string) (net.Addr, error) {
		addr, err := net.ResolveUDPAddr("udp4", str)
		if err != nil {
			return nil, err
		}
		return wrapAddr(addr), nil
	})

	transports.RegisterResolver("udp6", func(str string) (net.Addr, error) {
		addr, err := net.ResolveUDPAddr("udp6", str)
		if err != nil {
			return nil, err
		}
		return wrapAddr(addr), nil
	})
}

type udpAddr interface {
	dgram.Addr
	GetIP() net.IP
	GetPort() uint16
	ToUDPAddr() *net.UDPAddr
	IsIPv6() bool
}

type udpv4 net.UDPAddr
type udpv6 net.UDPAddr

var (
	_ nat.Addr = (*udpv4)(nil)
	_ nat.Addr = (*udpv6)(nil)
)

func ipIs4(ip net.IP) bool {
	if len(ip) == net.IPv4len {
		return true
	}
	if len(ip) == net.IPv6len &&
		isZeros(ip[0:10]) &&
		ip[10] == 0xff &&
		ip[11] == 0xff {
		return true
	}
	return false
}

func isZeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func wrapAddr(addr *net.UDPAddr) udpAddr {
	if ipIs4(addr.IP) {
		return (*udpv4)(addr)
	}
	return (*udpv6)(addr)
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

func (u *udpv4) FillKey(k []byte) {
	k[0] = 4
	copy(k[1:1+4], u.IP.To4())
	binary.BigEndian.PutUint16(k[1+4:], uint16(u.Port))
}
func (u *udpv6) FillKey(k []byte) {
	k[0] = 6
	copy(k[1:1+16], u.IP.To16())
	binary.BigEndian.PutUint16(k[1+16:], uint16(u.Port))
}

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

	*u = *addr.(*udpv4)
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
	if !addr.IsIPv6() {
		return transports.ErrInvalidAddr
	}

	*u = *addr.(*udpv6)
	return nil
}

func (u *udpv4) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}{
		Type: u.Network(),
		IP:   u.IP.String(),
		Port: u.Port,
	}

	return json.Marshal(&desc)
}

func (u *udpv6) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}{
		Type: u.Network(),
		IP:   u.IP.String(),
		Port: u.Port,
	}

	return json.Marshal(&desc)
}

func (u *udpv4) InternalAddr() (proto string, ip net.IP, port int) {
	return "udp", u.IP, u.Port
}

func (u *udpv6) InternalAddr() (proto string, ip net.IP, port int) {
	return "udp", u.IP, u.Port
}

func (u *udpv4) MakeGlobal(ip net.IP, port int) net.Addr {
	return wrapAddr(&net.UDPAddr{IP: ip, Port: port})
}

func (u *udpv6) MakeGlobal(ip net.IP, port int) net.Addr {
	return wrapAddr(&net.UDPAddr{IP: ip, Port: port})
}

func (u *udpv4) Equal(other net.Addr) bool {
	if b, ok := other.(*udpv4); ok {
		return bytes.Equal(u.IP.To4(), b.IP.To4()) && u.Port == b.Port
	}
	return false
}

func (u *udpv6) Equal(other net.Addr) bool {
	if b, ok := other.(*udpv6); ok {
		return bytes.Equal(u.IP.To16(), b.IP.To16()) && u.Port == b.Port
	}
	return false
}

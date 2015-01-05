package tcp

import (
	"encoding/json"
	"net"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/nat"
)

func init() {
	transports.RegisterAddr(&tcpv4{})
	transports.RegisterAddr(&tcpv6{})
}

type tcpAddr interface {
	net.Addr
	GetIP() net.IP
	GetPort() uint16
	ToTCPAddr() *net.TCPAddr
	IsIPv6() bool
}

type tcpv4 net.TCPAddr
type tcpv6 net.TCPAddr

var (
	_ nat.Addr = (*tcpv4)(nil)
	_ nat.Addr = (*tcpv6)(nil)
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

func wrapAddr(addr *net.TCPAddr) tcpAddr {
	if ipIs4(addr.IP) {
		return (*tcpv4)(addr)
	}
	return (*tcpv6)(addr)
}

func (u *tcpv4) Network() string { return "tcp4" }
func (u *tcpv6) Network() string { return "tcp6" }

func (u *tcpv4) String() string { return u.ToTCPAddr().String() }
func (u *tcpv6) String() string { return u.ToTCPAddr().String() }

func (u *tcpv4) GetIP() net.IP { return u.ToTCPAddr().IP }
func (u *tcpv6) GetIP() net.IP { return u.ToTCPAddr().IP }

func (u *tcpv4) GetPort() uint16 { return uint16(u.ToTCPAddr().Port) }
func (u *tcpv6) GetPort() uint16 { return uint16(u.ToTCPAddr().Port) }

func (u *tcpv4) ToTCPAddr() *net.TCPAddr { return (*net.TCPAddr)(u) }
func (u *tcpv6) ToTCPAddr() *net.TCPAddr { return (*net.TCPAddr)(u) }

func (u *tcpv4) IsIPv6() bool { return false }
func (u *tcpv6) IsIPv6() bool { return true }

func (u *tcpv4) UnmarshalJSON(data []byte) error {
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

	addr := wrapAddr(&net.TCPAddr{IP: ip, Port: desc.Port})
	if addr.IsIPv6() {
		return transports.ErrInvalidAddr
	}

	*u = *(addr).(*tcpv4)
	return nil
}

func (u *tcpv6) UnmarshalJSON(data []byte) error {
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

	addr := wrapAddr(&net.TCPAddr{IP: ip, Port: desc.Port})
	if addr.IsIPv6() {
		return transports.ErrInvalidAddr
	}

	*u = *addr.(*tcpv6)
	return nil
}

func (u *tcpv4) MarshalJSON() ([]byte, error) {
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

func (u *tcpv6) MarshalJSON() ([]byte, error) {
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

func (u *tcpv4) InternalAddr() (proto string, ip net.IP, port int) {
	return "tcp", u.IP, u.Port
}

func (u *tcpv6) InternalAddr() (proto string, ip net.IP, port int) {
	return "tcp", u.IP, u.Port
}

func (u *tcpv4) MakeGlobal(ip net.IP, port int) net.Addr {
	return wrapAddr(&net.TCPAddr{IP: ip, Port: port})
}

func (u *tcpv6) MakeGlobal(ip net.IP, port int) net.Addr {
	return wrapAddr(&net.TCPAddr{IP: ip, Port: port})
}

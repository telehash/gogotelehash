package ipv6

import (
	"bytes"
	"encoding/json"
	"errors"
	th "github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/iputil"
	"net"
	"strconv"
)

var (
	ErrInvalidIPv6Address = errors.New("invalid IPv6 address")
)

type Addr struct {
	Category iputil.Category
	IP       net.IP
	Zone     string
	Port     int
}

func ResolveAddr(str string) (th.Addr, error) {
	addr, err := net.ResolveUDPAddr("udp6", str)
	if err != nil {
		return nil, err
	}

	return format_addr(addr)
}

func (a *Addr) NeedNatHolePunching() bool {
	return a.Category == iputil.CategoryWAN
}

func (a *Addr) PublishWithConnect() bool {
	return a.Category == iputil.CategoryWAN
}

func (a *Addr) PublishWithPath() bool {
	return true
}

func (a *Addr) PublishWithPeer() bool {
	return a.Category == iputil.CategoryWAN
}

func (a *Addr) PublishWithSeek() bool {
	return false
}

func (a *Addr) SeekString() string {
	return ""
}

func (a *Addr) DefaultPriority() int {
	switch a.Category {
	case iputil.CategoryLocal:
		return 7
	case iputil.CategoryLAN:
		return 5
	case iputil.CategoryWAN:
		return 3
	default:
		return 0
	}
}

func (a *Addr) EqualTo(other th.Addr) bool {
	if b, ok := other.(*Addr); ok {
		return a.Category == b.Category && a.Port == b.Port && a.Zone == b.Zone && bytes.Equal(a.IP, b.IP)
	}
	return false
}

func (n *Addr) MarshalJSON() ([]byte, error) {
	var (
		j = struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}{
			IP:   n.IP.String(),
			Port: n.Port,
		}
	)

	return json.Marshal(j)
}

func (n *Addr) UnmarshalJSON(data []byte) error {
	var (
		j struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
	)

	err := json.Unmarshal(data, &j)
	if err != nil {
		return err
	}

	if j.IP == "" || j.Port == 0 {
		return ErrInvalidIPv6Address
	}

	a, err := ResolveAddr(net.JoinHostPort(j.IP, strconv.Itoa(j.Port)))
	if err != nil {
		return err
	}

	*n = *a.(*Addr)
	return nil
}

func format_addr(addri net.Addr) (th.Addr, error) {
	if addri == nil {
		return nil, nil
	}

	var (
		ip   net.IP
		zone string
		port int
		cat  iputil.Category
	)

	switch addr := addri.(type) {
	case *net.IPNet:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
		zone = addr.Zone
	case *net.UDPAddr:
		ip = addr.IP
		port = addr.Port
		zone = addr.Zone
	case *net.TCPAddr:
		ip = addr.IP
		port = addr.Port
		zone = addr.Zone
	}

	cat = iputil.CategoryFor(ip)

	if iputil.Version(ip) != 6 {
		return nil, ErrInvalidIPv6Address
	}

	return &Addr{cat, ip, zone, port}, nil
}

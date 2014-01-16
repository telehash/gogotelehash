package ipv6

import (
	"bytes"
	"errors"
	"fmt"
	th "github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/iputil"
	"net"
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

func (a *Addr) String() string {
	return fmt.Sprintf("%s:%d cat=%s", a.IP, a.Port, a.Category)
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

func format_addr(addri net.Addr) (*Addr, error) {
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

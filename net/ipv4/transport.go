package ipv4

import (
	"encoding/json"
	"errors"
	"github.com/telehash/gogotelehash"
	th "github.com/telehash/gogotelehash/net"
	"github.com/telehash/gogotelehash/net/iputil"
	"net"
	"strconv"
	"sync"
)

const network = "ipv4"

type Transport struct {
	Addr string
	conn *net.UDPConn
}

func (t *Transport) Network() string {
	return network
}

func (t *Transport) Start(sw *telehash.Switch, wg *sync.WaitGroup) error {
	addr, err := net.ResolveUDPAddr("udp4", t.Addr)
	if err != nil {
		return err
	}

	c, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}

	t.conn = c

	return nil
}

func (t *Transport) LocalAddresses() []th.Addr {
	laddr := t.conn.LocalAddr().(*net.UDPAddr)

	l, err := iputil.LocalAddresses()
	if err != nil {
		// err
		return nil
	}

	l4 := make([]th.Addr, 0, len(l))
	for _, a := range l {
		a4, err := format_addr(a)
		if err == nil {
			a4.Port = laddr.Port
			l4 = append(l4, a4)
		}
	}

	return l4
}

func (t *Transport) Stop() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *Transport) ReadFrom(b []byte) (int, th.Addr, error) {
	n, addr, err := t.conn.ReadFrom(b)
	if _net_conn_is_closed_err(err) {
		return 0, nil, th.ErrTransportClosed
	}
	if err != nil {
		return 0, nil, err
	}

	thaddr, err := format_addr(addr)
	if err != nil {
		return 0, nil, err
	}

	return n, thaddr, nil
}

func (t *Transport) WriteTo(b []byte, addr th.Addr) (int, error) {
	var (
		naddr net.UDPAddr
	)

	if a, ok := addr.(*Addr); ok {
		naddr.IP = a.IP
		naddr.Port = a.Port
	}

	n, err := t.conn.WriteTo(b, &naddr)
	if _net_conn_is_closed_err(err) {
		return 0, th.ErrTransportClosed
	}
	if err != nil {
		return 0, err
	}

	return n, err
}

func _net_conn_is_closed_err(err error) bool {
	if err == nil {
		return false
	}

	const s = "use of closed network connection"

	switch v := err.(type) {
	case *net.OpError:
		return _net_conn_is_closed_err(v.Err)
	default:
		return s == v.Error()
	}
}

func init() {
	th.RegisterSeeEncoder("ipv4", func(addr th.Addr) ([]string, error) {
		if a, ok := addr.(*Addr); ok && a != nil {
			return []string{a.IP.String(), strconv.Itoa(a.Port)}, nil
		}
		return nil, nil
	})

	th.RegisterSeeDecoder("ipv4", func(fields []string) (th.Addr, error) {
		if len(fields) != 2 {
			return nil, errors.New("invalid ipv4 see entry")
		}

		addr, err := ResolveAddr(net.JoinHostPort(fields[0], fields[1]))
		if err != nil {
			return nil, errors.New("invalid ipv4 see entry")
		}

		return addr, nil
	})

	th.RegisterPathEncoder("ipv4", func(n th.Addr) ([]byte, error) {
		a := n.(*Addr)

		var (
			j = struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}{
				IP:   a.IP.String(),
				Port: a.Port,
			}
		)

		return json.Marshal(j)
	})

	th.RegisterPathDecoder("ipv4", func(data []byte) (th.Addr, error) {
		var (
			j struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}
		)

		err := json.Unmarshal(data, &j)
		if err != nil {
			return nil, err
		}

		if j.IP == "" || j.Port == 0 {
			return nil, ErrInvalidIPv4Address
		}

		return ResolveAddr(net.JoinHostPort(j.IP, strconv.Itoa(j.Port)))
	})
}

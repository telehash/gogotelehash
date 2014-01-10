package ipv6

import (
	th "github.com/telehash/gogotelehash/net"
	"net"
)

type Transport struct {
	conn *net.UDPConn
}

func Open(addr string) (*Transport, error) {
	laddr, err := net.ResolveUDPAddr("udp6", addr)
	if err != nil {
		return nil, err
	}

	c, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		return nil, err
	}

	return &Transport{c}, nil
}

func (t *Transport) Close() error {
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
		naddr.Zone = a.Zone
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

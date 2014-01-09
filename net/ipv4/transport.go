package ipv4

import (
	th "github.com/telehash/gogotelehash/net"
	"net"
)

type Transport struct {
	conn *net.UDPConn
}

func Open(addr string) (*Transport, error) {
	laddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}

	c, err := net.ListenUDP("udp4", laddr)
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

}

func (t *Transport) WriteTo(b []byte, addr th.Addr) (int, error) {
	n, addr, err := t.conn.WriteTo(b, addr)
	if _net_conn_is_closed_err(err) {
		return 0, th.ErrTransportClosed
	}
	if err != nil {
		return 0, err
	}

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

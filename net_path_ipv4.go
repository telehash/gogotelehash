package telehash

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
)

type IPv4NetPath struct {
	cat            ip_addr_category
	IP             net.IP
	Port           int
	hash           uint32
	priority_delta net_path_priority
}

func (n *IPv4NetPath) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 8 + n.priority_delta.Get()
	case ip_lan:
		return 6 + n.priority_delta.Get()
	case ip_wan:
		return 4 + n.priority_delta.Get()
	default:
		return 0 + n.priority_delta.Get()
	}
}

func (n *IPv4NetPath) Demote() {
	n.priority_delta.Add(-1)
}

func (n *IPv4NetPath) Break() {
	n.priority_delta.Add(-3 - n.Priority())
}

func (n *IPv4NetPath) ResetPriority() {
	n.priority_delta.Reset()
}

func (n *IPv4NetPath) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "ipv4")
		fmt.Fprintln(h, n.IP.String())
		fmt.Fprintln(h, n.Port)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *IPv4NetPath) AddressForSeek() (string, int, bool) {
	if n.cat == ip_wan {
		return n.IP.String(), n.Port, true
	}
	return "", 0, false
}

func (n *IPv4NetPath) IncludeInConnect() bool {
	if n.cat == ip_wan {
		return true
	}
	return false
}

func (n *IPv4NetPath) SendNatBreaker() bool {
	return n.cat == ip_wan
}

func (n *IPv4NetPath) String() string {
	return fmt.Sprintf("<net-ipv4 %s %s port=%d>", n.IP, n.cat, n.Port)
}

func (n *IPv4NetPath) Send(sw *Switch, pkt *pkt_t) error {
	return ip_snd_pkt(sw, &net.UDPAddr{IP: n.IP, Port: n.Port}, pkt)
}

func (n *IPv4NetPath) MarshalJSON() ([]byte, error) {
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

func (n *IPv4NetPath) UnmarshalJSON(data []byte) error {
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
		return fmt.Errorf("Invalid IPv4 netpath")
	}

	m, err := ParseIPNetPath(net.JoinHostPort(j.IP, strconv.Itoa(j.Port)))
	if err != nil {
		return err
	}

	if o, ok := m.(*IPv4NetPath); ok {
		*n = *o
		return nil
	}

	return fmt.Errorf("Invalid IPv4 netpath")
}

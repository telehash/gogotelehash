package telehash

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
)

type IPv6net_path struct {
	cat            ip_addr_category
	IP             net.IP
	Zone           string
	Port           int
	hash           uint32
	priority_delta net_path_priority
}

func (n *IPv6net_path) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 7 + n.priority_delta.Get()
	case ip_lan:
		return 5 + n.priority_delta.Get()
	case ip_wan:
		return 3 + n.priority_delta.Get()
	default:
		return 0 + n.priority_delta.Get()
	}
}

func (n *IPv6net_path) Demote() {
	n.priority_delta.Add(-1)
}

func (n *IPv6net_path) Break() {
	n.priority_delta.Add(-3 - n.Priority())
}

func (n *IPv6net_path) ResetPriority() {
	n.priority_delta.Reset()
}

func (n *IPv6net_path) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "ipv6")
		fmt.Fprintln(h, n.IP.String())
		fmt.Fprintln(h, n.Port)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *IPv6net_path) AddressForSeek() (string, int, bool) {
	return "", 0, false // only IPv4 in seek/see
}

func (n *IPv6net_path) IncludeInConnect() bool {
	if n.cat == ip_wan {
		return true
	}
	return false
}

func (n *IPv6net_path) SendNatBreaker() bool {
	return n.cat == ip_wan
}

func (n *IPv6net_path) String() string {
	return fmt.Sprintf("<net-ipv6 %s%%%s %s port=%d>", n.IP, n.Zone, n.cat, n.Port)
}

func (n *IPv6net_path) Send(sw *Switch, pkt *pkt_t) error {
	return ip_snd_pkt(sw, &net.UDPAddr{IP: n.IP, Port: n.Port}, pkt)
}

func (n *IPv6net_path) MarshalJSON() ([]byte, error) {
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

func (n *IPv6net_path) UnmarshalJSON(data []byte) error {
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
		return fmt.Errorf("Invalid IPv6 netpath")
	}

	m, err := ParseIPnet_path(net.JoinHostPort(j.IP, strconv.Itoa(j.Port)))
	if err != nil {
		return err
	}

	if o, ok := m.(*IPv6net_path); ok {
		*n = *o
		return nil
	}

	return fmt.Errorf("Invalid IPv6 netpath")
}

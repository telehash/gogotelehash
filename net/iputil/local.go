package iputil

import (
	"net"
)

func LocalAddresses() ([]net.Addr, error) {
	var (
		nets []net.Addr
	)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			nets = append(nets, addr)
		}
	}

	return nets, nil
}

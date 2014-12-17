package transportsutil

import (
	"net"
)

func InterfaceIPs() ([]*net.IPAddr, error) {
	var (
		addrs []*net.IPAddr
	)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		iaddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, iaddr := range iaddrs {
			var (
				ip   net.IP
				zone string
			)

			switch x := iaddr.(type) {
			case *net.IPAddr:
				ip = x.IP
				zone = x.Zone
			case *net.IPNet:
				ip = x.IP
				zone = ""
			}

			if ip.IsMulticast() ||
				ip.IsUnspecified() ||
				ip.IsInterfaceLocalMulticast() ||
				ip.IsLinkLocalMulticast() ||
				ip.IsLinkLocalUnicast() {
				continue
			}

			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}

			addrs = append(addrs, &net.IPAddr{
				IP:   ip,
				Zone: zone,
			})
		}
	}

	return addrs, nil
}

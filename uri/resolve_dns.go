package uri

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
)

func resolveSRV(uri *URI, proto string) (*e3x.Identity, error) {
	// ignore port
	host, _, _ := net.SplitHostPort(uri.Canonical)
	if host == "" {
		host = uri.Canonical
	}

	// normalize
	if !strings.HasSuffix(host, ".") {
		host += "."
	}

	// ignore .public
	if strings.HasSuffix(host, ".public.") {
		return nil, &net.DNSError{Name: host, Err: "cannot resolve .public hostnames using DNS"}
	}

	// lookup SRV records
	_, srvs, err := net.LookupSRV("mesh", proto, host)
	if err != nil {
		return nil, err
	}
	if len(srvs) > 1 {
		return nil, &net.DNSError{Name: host, Err: "too many SRV records"}
	}
	if len(srvs) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no SRV records"}
	}

	var (
		srv     = srvs[0]
		port    = srv.Port
		portStr = strconv.Itoa(int(port))
		hn      hashname.H
		keys    cipherset.Keys
	)

	{ // detect valid target
		parts := strings.SplitN(srv.Target, ".", 2)
		if len(parts) != 2 || len(parts[0]) != 52 || len(parts[1]) == 0 {
			return nil, &net.DNSError{Name: host, Err: "SRV must target a <hashname>.<domain> domain"}
		}

		hn = hashname.H(parts[0])
		if !hn.Valid() {
			return nil, &net.DNSError{Name: host, Err: "SRV must target a <hashname>.<domain> domain"}
		}
	}

	// detect CNAMEs (they are not allowed)
	cname, err := net.LookupCNAME(srv.Target)
	if err != nil {
		return nil, err
	}
	if cname != "" && cname != srv.Target {
		return nil, &net.DNSError{Name: host, Err: "CNAME record are not allowed"}
	}

	// lookup A AAAA records
	ips, err := net.LookupIP(srv.Target)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no A or AAAA records"}
	}

	// lookup TXT
	txts, err := net.LookupTXT(srv.Target)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, &net.DNSError{Name: host, Err: "no TXT records"}
	}

	// make addrs
	addrs := make([]net.Addr, 0, len(ips))
	for _, ip := range ips {
		var (
			addr net.Addr
		)

		switch proto {
		case "udp":
			addr, _ = transports.ResolveAddr("udp4", net.JoinHostPort(ip.String(), portStr))
			if addr == nil {
				addr, _ = transports.ResolveAddr("udp6", net.JoinHostPort(ip.String(), portStr))
			}
		case "tcp":
			addr, _ = transports.ResolveAddr("tcp4", net.JoinHostPort(ip.String(), portStr))
			if addr == nil {
				addr, _ = transports.ResolveAddr("tcp6", net.JoinHostPort(ip.String(), portStr))
			}
			// case "http":
			// 	addr, _ = http.NewAddr(ip, port)
		}

		if addr != nil {
			addrs = append(addrs, addr)
		}
	}

	{ // parse keys

		// Sort txts so they form ascending sequences of key parts
		sort.Strings(txts)

		keyData := make(map[uint8]string, 10)
		for len(txts) > 0 {
			var (
				txt   = txts[0]
				parts = strings.Split(txt, "=")
			)

			if len(parts) != 2 {
				txts = txts[1:]
				continue
			}

			var (
				label = parts[0]
				value = parts[1]
				csid  uint8
			)

			if len(label) < 2 {
				txts = txts[1:]
				continue
			}

			// parse the CSID portion of the label
			i, err := strconv.ParseUint(label[:2], 16, 8)
			if err != nil {
				txts = txts[1:]
				continue
			}
			csid = uint8(i)

			// verify the key-part portion of the label
			if len(label) > 2 {
				_, err = strconv.ParseUint(label[2:], 10, 8)
				if err != nil {
					txts = txts[1:]
					continue
				}
			}

			keyData[csid] += value
			txts = txts[1:]
		}

		keys = make(cipherset.Keys, len(keyData))
		for csid, str := range keyData {
			key, err := cipherset.DecodeKey(csid, str, "")
			if err != nil {
				continue
			}

			keys[csid] = key
		}
	}

	ident, err := e3x.NewIdentity(keys, nil, addrs)
	if err != nil {
		return nil, err
	}

	if hn != ident.Hashname() {
		return nil, &net.DNSError{Name: host, Err: "invalid keys"}
	}

	return ident, nil
}

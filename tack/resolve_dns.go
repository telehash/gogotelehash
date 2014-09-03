package tack

import (
	"net"
)

func resolveSRVWithProto(proto string, t *Tack) {
	cname, srvs, err := net.LookupSRV("tack", "udp", t.Canonical)
	for _, srv := range srvs {

	}
}

func resolveSRV(t *Tack) {
	resolveSRVWithProto("udp", t)
	resolveSRVWithProto("tcp", t)
}

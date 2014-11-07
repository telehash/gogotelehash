package uri

import (
	"github.com/telehash/gogotelehash/e3x"
)

func Resolve(uri *URI) (*e3x.Ident, error) {
	// Resolve order:
	// - .public (if available)
	// - DNS-SRV-udp
	// - DNS-SRV-tcp
	// - DNS-SRV-http
	// - HTTP-well-known
	var (
		ident *e3x.Ident
		err   error
	)

	ident, err = resolveSRV(uri, "udp")
	if ident != nil {
		return ident, nil
	}

	ident, err = resolveSRV(uri, "tcp")
	if ident != nil {
		return ident, nil
	}

	ident, err = resolveSRV(uri, "http")
	if ident != nil {
		return ident, nil
	}

	ident, err = resolveHTTP(uri)
	if ident != nil {
		return ident, nil
	}

	return nil, err
}

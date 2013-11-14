package telehash

import (
	"crypto/rsa"
	"encoding/hex"
	"net/url"
	"path"
)

func (s *Switch) SeedURL() (string, error) {
	der, err := enc_DER_RSA(&s.key.PublicKey)
	if err != nil {
		return "", err
	}

	b64 := hex.EncodeToString(der)

	u := url.URL{
		Scheme: "telehash",
		Host:   s.addr,
		Path:   "/" + b64,
	}

	return u.String(), nil
}

func ParseSeedURL(rawurl string) (addr string, pubkey *rsa.PublicKey, err error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", nil, err
	}

	addr = u.Host

	der, err := hex.DecodeString(path.Base(u.Path))
	if err != nil {
		return "", nil, err
	}

	key, err := dec_DER_RSA(der)
	if err != nil {
		return "", nil, err
	}

	return addr, key, nil
}

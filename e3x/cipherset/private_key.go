package cipherset

import (
	"github.com/telehash/gogotelehash/e3x/cipherset/driver"
)

// PrivateKey is a private key (accompanied by its public key) in binary format.
type PrivateKey struct {
	Private Key `json:"prv,omitempty"`
	Public  Key `json:"pub,omitempty"`
}

func GenerateKey(csid CSID) (*PrivateKey, error) {
	drv := driver.Lookup(uint8(csid))
	if drv == nil {
		return nil, ErrUnknownCSID
	}

	prv, pub, err := drv.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &PrivateKey{prv, pub}, nil
}

func GenerateKeys(csids ...CSID) (map[CSID]*PrivateKey, error) {

	keys := make(map[CSID]*PrivateKey, len(csids))
	for _, csid := range csids {
		key, err := GenerateKey(csid)
		if err != nil {
			return nil, err
		}
		keys[csid] = key
	}

	if len(csids) == 0 {
		for _, csid := range driver.AvailableCSIDs() {
			key, err := GenerateKey(CSID(csid))
			if err != nil {
				return nil, err
			}
			keys[CSID(csid)] = key
		}

	}

	return keys, nil
}

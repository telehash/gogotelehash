package cipherset

import (
	"encoding/hex"
	"errors"
)

var ErrInvalidKeys = errors.New("chipherset: invalid keys")
var ErrInvalidParts = errors.New("chipherset: invalid parts")

type Keys map[uint8]Key
type Parts map[uint8]string

func SelectCSID(a, b Keys) uint8 {
	var max uint8
	for csid := range a {
		if _, f := b[csid]; f && csid > max {
			max = csid
		}
	}
	return max
}

func KeysFromJSON(i interface{}) (Keys, error) {
	if i == nil {
		return nil, nil
	}

	x, ok := i.(map[string]interface{})
	if !ok {
		return nil, ErrInvalidKeys
	}

	if x == nil || len(x) == 0 {
		return nil, nil
	}

	y := make(Keys, len(x))
	for k, v := range x {
		if len(k) != 2 {
			return nil, ErrInvalidKeys
		}

		s, ok := v.(string)
		if !ok || s == "" {
			return nil, ErrInvalidKeys
		}

		csid, err := hex.DecodeString(k)
		if err != nil {
			return nil, ErrInvalidKeys
		}

		key, err := DecodeKey(csid[0], s)
		if err != nil {
			return nil, ErrInvalidKeys
		}

		y[csid[0]] = key
	}

	return y, nil
}

func PartsFromJSON(i interface{}) (Parts, error) {
	if i == nil {
		return nil, nil
	}

	x, ok := i.(map[string]interface{})
	if !ok {
		return nil, ErrInvalidParts
	}

	if x == nil || len(x) == 0 {
		return nil, nil
	}

	y := make(Parts, len(x))
	for k, v := range x {
		if len(k) != 2 {
			return nil, ErrInvalidParts
		}

		s, ok := v.(string)
		if !ok || s == "" {
			return nil, ErrInvalidParts
		}

		csid, err := hex.DecodeString(k)
		if err != nil {
			return nil, ErrInvalidParts
		}

		if len(s) != 52 {
			return nil, ErrInvalidParts
		}

		y[csid[0]] = s
	}

	return y, nil
}

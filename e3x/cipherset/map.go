package cipherset

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"bitbucket.org/simonmenke/go-telehash/base32"
	"bitbucket.org/simonmenke/go-telehash/lob"
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
			keyData, err := base32.DecodeString(s)
			if err != nil {
				return nil, ErrInvalidKeys
			}

			key = opaqueKey(keyData)
			err = nil
		}

		y[csid[0]] = key
	}

	return y, nil
}

// func PartsFromJSON(i interface{}) (Parts, error) {
//   if i == nil {
//     return nil, nil
//   }

//   x, ok := i.(map[string]interface{})
//   if !ok {
//     return nil, ErrInvalidParts
//   }

//   if x == nil || len(x) == 0 {
//     return nil, nil
//   }

//   y := make(Parts, len(x))
//   for k, v := range x {
//     if len(k) != 2 {
//       return nil, ErrInvalidParts
//     }

//     s, ok := v.(string)
//     if !ok || s == "" {
//       return nil, ErrInvalidParts
//     }

//     csid, err := hex.DecodeString(k)
//     if err != nil {
//       return nil, ErrInvalidParts
//     }

//     if len(s) != 52 {
//       return nil, ErrInvalidParts
//     }

//     y[csid[0]] = s
//   }

//   return y, nil
// }

func PartsFromHeader(h lob.Header) (Parts, error) {
	if h == nil || len(h) == 0 {
		return nil, nil
	}

	y := make(Parts, len(h))
	for k, v := range h {
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

func (p Parts) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(p))
	for k, v := range p {
		m[hex.EncodeToString([]byte{k})] = v
	}
	return json.Marshal(m)
}

func (p Keys) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(p))
	for k, v := range p {
		m[hex.EncodeToString([]byte{k})] = v.String()
	}
	return json.Marshal(m)
}

func (k *Keys) UnmarshalJSON(data []byte) error {
	var (
		x   map[string]string
		err = json.Unmarshal(data, &x)
	)

	if err != nil {
		return err
	}

	y := make(Keys, len(x))
	*k = y
	for k, s := range x {
		if len(k) != 2 {
			return ErrInvalidKeys
		}

		if s == "" {
			return ErrInvalidKeys
		}

		csid, err := hex.DecodeString(k)
		if err != nil {
			return ErrInvalidKeys
		}

		key, err := DecodeKey(csid[0], s)
		if err != nil {
			keyData, err := base32.DecodeString(s)
			if err != nil {
				return ErrInvalidKeys
			}

			key = opaqueKey(keyData)
			err = nil
		}

		y[csid[0]] = key
	}

	return nil
}

func (p *Parts) UnmarshalJSON(data []byte) error {
	var (
		x   map[string]string
		err = json.Unmarshal(data, &x)
	)

	if err != nil {
		return err
	}

	y := make(Parts, len(x))
	*p = y
	for k, s := range x {
		if len(k) != 2 {
			return ErrInvalidParts
		}

		if s == "" {
			return ErrInvalidParts
		}

		csid, err := hex.DecodeString(k)
		if err != nil {
			return ErrInvalidParts
		}

		if len(s) != 52 {
			return ErrInvalidParts
		}

		y[csid[0]] = s
	}

	return nil
}

func (p Parts) ApplyToHeader(h lob.Header) {
	for k, v := range p {
		h.Set(hex.EncodeToString([]byte{k}), v)
	}
}

func (p Keys) ApplyToHeader(h lob.Header) {
	for k, v := range p {
		h.Set(hex.EncodeToString([]byte{k}), v.String())
	}
}

type opaqueKey []byte

func (o opaqueKey) String() string {
	return base32.EncodeToString(o)
}

func (o opaqueKey) Bytes() []byte {
	return o
}

func (o opaqueKey) CanSign() bool {
	return false
}

func (o opaqueKey) CanEncrypt() bool {
	return false
}

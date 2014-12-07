package cipherset

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/util/base32util"
)

var ErrInvalidKeys = errors.New("chipherset: invalid keys")
var ErrInvalidParts = errors.New("chipherset: invalid parts")

type Keys map[uint8]Key
type PrivateKeys Keys
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

		key, err := DecodeKey(csid[0], s, "")
		if err != nil {
			return nil, err
		}

		y[csid[0]] = key
	}

	return y, nil
}

func PartsFromHeader(h *lob.Header) (Parts, error) {
	if h.IsZero() {
		return nil, nil
	}

	y := make(Parts, len(h.Extra))
	for k, v := range h.Extra {
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

func (k Keys) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(k))
	for csid, v := range k {
		m[hex.EncodeToString([]byte{csid})] = v.String()
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

		key, err := DecodeKey(csid[0], s, "")
		if err != nil {
			return err
		}

		y[csid[0]] = key
	}

	return nil
}

func (p PrivateKeys) MarshalJSON() ([]byte, error) {
	type pair struct {
		Pub string `json:"pub,omitempty"`
		Prv string `json:"prv,omitempty"`
	}

	m := make(map[string]pair, len(p))
	for k, v := range p {
		m[hex.EncodeToString([]byte{k})] = pair{
			Pub: base32util.EncodeToString(v.Public()),
			Prv: base32util.EncodeToString(v.Private()),
		}
	}

	return json.Marshal(m)
}

func (p *PrivateKeys) UnmarshalJSON(data []byte) error {
	type pair struct {
		Pub string `json:"pub,omitempty"`
		Prv string `json:"prv,omitempty"`
	}

	var (
		x   map[string]pair
		err = json.Unmarshal(data, &x)
	)

	if err != nil {
		return err
	}

	y := make(PrivateKeys, len(x))
	*p = y
	for csidHex, pair := range x {
		if len(csidHex) != 2 {
			return ErrInvalidKeys
		}

		if pair.Pub == "" {
			return ErrInvalidKeys
		}

		csid, err := hex.DecodeString(csidHex)
		if err != nil {
			return ErrInvalidKeys
		}

		key, err := DecodeKey(csid[0], pair.Pub, pair.Prv)
		if err != nil {
			return err
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

func (p Parts) ApplyToHeader(h *lob.Header) {
	for k, v := range p {
		h.Set(hex.EncodeToString([]byte{k}), v)
	}
}

func (k Keys) ApplyToHeader(h *lob.Header) {
	for csid, v := range k {
		h.Set(hex.EncodeToString([]byte{csid}), v.String())
	}
}

type opaqueKey struct {
	csid     uint8
	pub, prv []byte
}

func (o opaqueKey) String() string {
	return base32util.EncodeToString(o.pub)
}

func (o opaqueKey) Public() []byte {
	return o.pub
}

func (o opaqueKey) Private() []byte {
	return o.prv
}

func (o opaqueKey) CanSign() bool {
	return false
}

func (o opaqueKey) CanEncrypt() bool {
	return false
}

func (o opaqueKey) CSID() uint8 {
	return o.csid
}

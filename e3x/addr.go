package e3x

import (
	"encoding/json"
	"errors"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/transports"
)

var ErrNoKeys = errors.New("e3x: no keys")
var ErrNoAddress = errors.New("e3x: no addresses")

type Addr struct {
	hashname hashname.H
	keys     cipherset.Keys
	parts    cipherset.Parts
	addrs    []transports.Addr
}

func NewAddr(keys cipherset.Keys, parts cipherset.Parts, addrs []transports.Addr) (*Addr, error) {
	var err error

	addr := &Addr{
		keys:  keys,
		parts: parts,
		addrs: addrs,
	}

	if len(addr.keys) == 0 {
		return nil, ErrNoKeys
	}

	if len(addr.addrs) == 0 {
		return nil, ErrNoAddress
	}

	if addr.parts == nil {
		addr.parts = make(cipherset.Parts, len(addr.keys))
	}

	for csid, part := range hashname.PartsFromKeys(addr.keys) {
		addr.parts[csid] = part
	}

	addr.hashname, err = hashname.FromIntermediates(addr.parts)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

func (a *Addr) Hashname() hashname.H {
	return a.hashname
}

func (a *Addr) String() string {
	return string(a.hashname)
}

func (a *Addr) MarshalJSON() ([]byte, error) {
	var jsonAddr = struct {
		Hashname hashname.H        `json:"hashname"`
		Keys     cipherset.Keys    `json:"keys"`
		Parts    cipherset.Parts   `json:"parts"`
		Addrs    []transports.Addr `json:"paths"`
	}{a.hashname, a.keys, a.parts, a.addrs}
	return json.Marshal(&jsonAddr)
}

func (a *Addr) UnmarshalJSON(p []byte) error {
	var jsonAddr struct {
		Hashname hashname.H        `json:"hashname"`
		Keys     cipherset.Keys    `json:"keys"`
		Parts    cipherset.Parts   `json:"parts"`
		Addrs    []json.RawMessage `json:"paths"`
	}
	err := json.Unmarshal(p, &jsonAddr)
	if err != nil {
		return err
	}

	var addrs []transports.Addr
	for _, m := range jsonAddr.Addrs {
		addr, err := transports.DecodeAddr(m)
		if err != nil {
			return err
		}

		addrs = append(addrs, addr)
	}

	b, err := NewAddr(jsonAddr.Keys, jsonAddr.Parts, addrs)
	if err != nil {
		return err
	}

	*a = *b
	return nil
}

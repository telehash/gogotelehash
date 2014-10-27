package e3x

import (
	"encoding/json"
	"errors"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var ErrNoKeys = errors.New("e3x: no keys")
var ErrNoAddress = errors.New("e3x: no addresses")

type Ident struct {
	hashname hashname.H
	keys     cipherset.Keys
	parts    cipherset.Parts
	addrs    []transports.Addr
}

func NewIdent(keys cipherset.Keys, parts cipherset.Parts, addrs []transports.Addr) (*Ident, error) {
	var err error

	ident := &Ident{
		keys:  keys,
		parts: parts,
		addrs: addrs,
	}

	if len(ident.keys) == 0 {
		return nil, ErrNoKeys
	}

	if len(ident.addrs) == 0 {
		return nil, ErrNoAddress
	}

	if ident.parts == nil {
		ident.parts = make(cipherset.Parts, len(ident.keys))
	}

	for csid, part := range hashname.PartsFromKeys(ident.keys) {
		ident.parts[csid] = part
	}

	ident.hashname, err = hashname.FromIntermediates(ident.parts)
	if err != nil {
		return nil, err
	}

	return ident, nil
}

func (ident *Ident) Hashname() hashname.H {
	return ident.hashname
}

func (ident *Ident) String() string {
	return string(ident.hashname)
}

func (ident *Ident) MarshalJSON() ([]byte, error) {
	var jsonAddr = struct {
		Hashname hashname.H        `json:"hashname"`
		Keys     cipherset.Keys    `json:"keys"`
		Parts    cipherset.Parts   `json:"parts"`
		Addrs    []transports.Addr `json:"paths"`
	}{ident.hashname, ident.keys, ident.parts, ident.addrs}
	return json.Marshal(&jsonAddr)
}

func (ident *Ident) UnmarshalJSON(p []byte) error {
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

	b, err := NewIdent(jsonAddr.Keys, jsonAddr.Parts, addrs)
	if err != nil {
		return err
	}

	*ident = *b
	return nil
}

func (ident *Ident) withPaths(paths []transports.Addr) *Ident {
	return &Ident{
		hashname: ident.hashname,
		keys:     ident.keys,
		parts:    ident.parts,
		addrs:    paths,
	}
}

func (ident *Ident) Keys() cipherset.Keys {
	return ident.keys
}

func (ident *Ident) Addresses() []transports.Addr {
	return ident.addrs
}

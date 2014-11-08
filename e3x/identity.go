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

type Identity struct {
	hashname hashname.H
	keys     cipherset.Keys
	parts    cipherset.Parts
	addrs    []transports.Addr
}

func NewIdentity(keys cipherset.Keys, parts cipherset.Parts, addrs []transports.Addr) (*Identity, error) {
	var err error

	ident := &Identity{
		keys:  keys,
		parts: parts,
		addrs: addrs,
	}

	if len(ident.keys) == 0 {
		return nil, ErrNoKeys
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

func (i *Identity) Hashname() hashname.H {
	return i.hashname
}

func (i *Identity) String() string {
	return string(i.hashname)
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	var jsonAddr = struct {
		Hashname hashname.H        `json:"hashname"`
		Keys     cipherset.Keys    `json:"keys"`
		Parts    cipherset.Parts   `json:"parts"`
		Addrs    []transports.Addr `json:"paths"`
	}{i.hashname, i.keys, i.parts, i.addrs}
	return json.Marshal(&jsonAddr)
}

func (i *Identity) UnmarshalJSON(p []byte) error {
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

	b, err := NewIdentity(jsonAddr.Keys, jsonAddr.Parts, addrs)
	if err != nil {
		return err
	}

	*i = *b
	return nil
}

func (i *Identity) withPaths(paths []transports.Addr) *Identity {
	return &Identity{
		hashname: i.hashname,
		keys:     i.keys,
		parts:    i.parts,
		addrs:    paths,
	}
}

func (i *Identity) Keys() cipherset.Keys {
	return i.keys
}

func (i *Identity) Addresses() []transports.Addr {
	return i.addrs
}

func (i *Identity) Identify(e *Endpoint) (*Identity, error) {
	return i, nil
}

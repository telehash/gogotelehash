package e3x

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/transports"
)

var ErrNoKeys = errors.New("e3x: no keys")
var ErrNoAddress = errors.New("e3x: no addresses")

type Identity struct {
	hashname hashname.H
	keys     cipherset.Keys
	parts    cipherset.Parts
	addrs    []net.Addr
}

func NewIdentity(hashname hashname.H) *Identity {
	return &Identity{hashname: hashname}
}

func (i *Identity) HasKeys() bool {
	if i == nil {
		return false
	}
	return len(i.keys) > 0
}

func (i *Identity) WithKeys(keys cipherset.Keys, parts cipherset.Parts) (*Identity, error) {
	var addrs []net.Addr

	if len(keys) == 0 {
		return nil, ErrNoKeys
	}

	if parts == nil {
		parts = make(cipherset.Parts, len(keys))
	}

	for csid, part := range keys.ToParts() {
		parts[csid] = part
	}

	hashname := parts.ToHashname()
	if hashname == "" {
		return nil, errors.New("e3x: invalid keys")
	}

	if i != nil {
		if i.hashname != "" && i.hashname != hashname {
			return nil, errors.New("e3x: mismatching keys")
		}

		addrs = i.addrs
	}

	i = &Identity{
		hashname: hashname,
		keys:     keys,
		parts:    parts,
		addrs:    addrs,
	}

	return i, nil
}

func (i *Identity) WithKeyAndParts(csid cipherset.CSID, key cipherset.Key, parts cipherset.Parts) (*Identity, error) {
	return i.WithKeys(cipherset.Keys{csid: key}, parts)
}

func (i *Identity) Hashname() hashname.H {
	return i.hashname
}

func (i *Identity) String() string {
	return string(i.hashname)
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	var jsonAddr = struct {
		Hashname hashname.H      `json:"hashname"`
		Keys     cipherset.Keys  `json:"keys"`
		Parts    cipherset.Parts `json:"parts"`
		Addrs    []net.Addr      `json:"paths"`
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

	var addrs []net.Addr
	for _, m := range jsonAddr.Addrs {
		addr, err := transports.DecodeAddr(m)
		if err != nil {
			return err
		}

		addrs = append(addrs, addr)
	}

	b, err := NewIdentity(jsonAddr.Hashname).WithAddrs(addrs).WithKeys(jsonAddr.Keys, jsonAddr.Parts)
	if err != nil {
		return err
	}

	*i = *b
	return nil
}

func (i *Identity) WithAddrs(addrs []net.Addr) *Identity {
	return &Identity{
		hashname: i.hashname,
		keys:     i.keys,
		parts:    i.parts,
		addrs:    addrs,
	}
}

func (i *Identity) AddPathCandiate(addr net.Addr) *Identity {
	var paths = make([]net.Addr, len(i.addrs), len(i.addrs)+1)
	copy(paths, i.addrs)
	paths = append(paths, addr)

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

func (i *Identity) Addresses() []net.Addr {
	return i.addrs
}

func (i *Identity) Identify(e *Endpoint) (*Identity, error) {
	return i, nil
}

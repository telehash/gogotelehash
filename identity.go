package telehash

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

type Identity struct {
	hashname Hashname
	paths    net_paths
	pubkey   *rsa.PublicKey
	prvkey   *rsa.PrivateKey
	pools    []string
}

func (i *Identity) Hashname() Hashname          { return i.hashname }
func (i *Identity) net_paths() net_paths        { return i.paths }
func (i *Identity) PublicKey() *rsa.PublicKey   { return i.pubkey }
func (i *Identity) PrivateKey() *rsa.PrivateKey { return i.prvkey }
func (i *Identity) Pools() []string             { return i.pools }

func (s *Switch) Identity() *Identity {
	if s == nil {
		return nil
	}

	ident := &Identity{
		hashname: s.LocalHashname(),
		pubkey:   &s.Key.PublicKey,
	}

	for _, t := range s.transports {
		for _, a := range t.LocalAddresses() {
			ident.paths = append(ident.paths, &net_path{Network: t.Network(), Address: a})
		}
	}

	return ident
}

func (i *Identity) ToPeer(sw *Switch) *Peer {
	if i == nil {
		return nil
	}

	peer := sw.GetPeer(i.hashname, true)

	if peer.pubkey == nil {
		peer.pubkey = i.pubkey
	}

	for _, np := range i.paths {
		peer.add_net_path(np)
	}

	return peer
}

func LoadIdenities(path string) ([]*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		l []*Identity
	)

	err = json.NewDecoder(f).Decode(l)
	if err != nil {
		return nil, err
	}

	return l, nil
}

type json_identity struct {
	Hashname string        `json:"hashname,omitempty"`
	Pools    []string      `json:"pools,omitempty"`
	Paths    raw_net_paths `json:"paths"`
	Public   string        `json:"public"`
	Private  string        `json:"private,omitempty"`
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	var (
		j      json_identity
		pubder []byte
		prvder []byte
		paths  raw_net_paths
		err    error
	)

	if i.pubkey != nil {
		pubder, err = x509.MarshalPKIXPublicKey(i.pubkey)
		if err != nil {
			return nil, err
		}
	}

	if i.prvkey != nil {
		pubder = x509.MarshalPKCS1PrivateKey(i.prvkey)
	}

	if len(i.paths) > 0 {
		paths, err = encode_net_paths(i.paths)
		if err != nil {
			return nil, err
		}
	}

	j = json_identity{
		Hashname: i.hashname.String(),
		Pools:    i.pools,
		Paths:    paths,
		Public:   base64.StdEncoding.EncodeToString(pubder),
		Private:  base64.StdEncoding.EncodeToString(prvder),
	}

	return json.Marshal(&j)
}

func (i *Identity) UnmarshalJSON(data []byte) error {
	var (
		j json_identity
		k Identity
	)

	err := json.Unmarshal(data, &j)
	if err != nil {
		return err
	}

	if len(j.Pools) > 0 {
		k.pools = j.Pools
	}

	if len(j.Paths) > 0 {
		paths, err := decode_net_paths(j.Paths)
		if err != nil {
			return err
		}

		k.paths = paths
	}

	if j.Hashname != "" {
		hashname, err := HashnameFromString(j.Hashname)
		if err != nil {
			return err
		}

		k.hashname = hashname
	}

	if j.Public != "" {
		pubder, err := base64.StdEncoding.DecodeString(j.Public)
		if err != nil {
			return err
		}

		pubkeyi, err := x509.ParsePKIXPublicKey(pubder)
		if err != nil {
			return err
		}

		pubkey, ok := pubkeyi.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected an RSA public key")
		}

		hashname, err := HashnameFromPublicKey(pubkey)
		if err != nil {
			return err
		}

		k.hashname = hashname
		k.pubkey = pubkey
	}

	if j.Private != "" {
		prvder, err := base64.StdEncoding.DecodeString(j.Private)
		if err != nil {
			return err
		}

		prvkey, err := x509.ParsePKCS1PrivateKey(prvder)
		if err != nil {
			return err
		}

		pubkey := &prvkey.PublicKey

		hashname, err := HashnameFromPublicKey(pubkey)
		if err != nil {
			return err
		}

		k.hashname = hashname
		k.pubkey = pubkey
		k.prvkey = prvkey
	}

	*i = k
	return nil
}

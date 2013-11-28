package telehash

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/gokyle/ecdh"
	"time"
)

type private_line_key struct {
	id         string
	rsa_pubkey *rsa.PublicKey   // the public RSA key of the remote switch
	rsa_prvkey *rsa.PrivateKey  // the private RSA key of the local switch
	ecc_prvkey *ecdh.PrivateKey // the private ECC key of the local switch

	enc_key_inner_pkt     []byte
	enc_key_inner_pkt_sig []byte
	public_line_key       public_line_key
}

type public_line_key struct {
	hashname       Hashname
	id             string
	rsa_pubkey     *rsa.PublicKey
	ecc_pubkey     *ecdh.PublicKey
	ecc_pubkey_enc []byte // encrypted public ECC key

	// these get set when (de-)composing an open packet
	to Hashname
	at time.Time
}

type shared_line_key struct {
	prv_half *private_line_key // owned by the local
	pub_half *public_line_key  // owned by the remote
	enc_key  []byte
	dec_key  []byte
}

func make_line_half(local *rsa.PrivateKey, remote *rsa.PublicKey) (*private_line_key, error) {

	bin_line_id, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	hex_line_id := hex.EncodeToString(bin_line_id)

	hashname, err := HashnameFromPublicKey(remote)
	if err != nil {
		return nil, err
	}

	ecc_prvkey, err := ecdh.GenerateKey(rand.Reader, elliptic.P256())
	if err != nil {
		return nil, err
	}

	ecc_pubkey_data := elliptic.Marshal(ecc_prvkey.PublicKey.Curve, ecc_prvkey.PublicKey.X, ecc_prvkey.PublicKey.Y)
	enc_key_inner_pkt := hash_SHA256(ecc_pubkey_data)
	enc_key_inner_pkt_sig := hash_SHA256(ecc_pubkey_data, bin_line_id)

	ecc_pubkey_enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, remote, ecc_pubkey_data, nil)
	if err != nil {
		return nil, err
	}

	prv_half := &private_line_key{
		id:                    hex_line_id,
		rsa_pubkey:            remote,
		rsa_prvkey:            local,
		ecc_prvkey:            ecc_prvkey,
		enc_key_inner_pkt:     enc_key_inner_pkt,
		enc_key_inner_pkt_sig: enc_key_inner_pkt_sig,

		public_line_key: public_line_key{
			hashname:       hashname,
			id:             hex_line_id,
			rsa_pubkey:     &local.PublicKey,
			ecc_pubkey:     &ecc_prvkey.PublicKey,
			ecc_pubkey_enc: ecc_pubkey_enc,
		},
	}

	return prv_half, nil
}

func (p *private_line_key) compose_open_pkt() (*pkt_t, error) {
	iv, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	rsa_pubkey_der, err := enc_DER_RSA(p.public_line_key.rsa_pubkey)
	if err != nil {
		return nil, err
	}

	ipkt := pkt_t{
		hdr: pkt_hdr_t{
			To:   p.public_line_key.hashname.String(),
			At:   time.Now().UnixNano() / 1000000,
			Line: p.id,
		},
		body: rsa_pubkey_der,
	}

	ipkt_data, err := ipkt.format_pkt()
	if err != nil {
		return nil, err
	}

	ipkt_data_enc, err := enc_AES_256_CTR(p.enc_key_inner_pkt, iv, ipkt_data)
	if err != nil {
		return nil, err
	}

	ipkt_data_sig, err := rsa.SignPKCS1v15(rand.Reader, p.rsa_prvkey, crypto.SHA256, hash_SHA256(ipkt_data_enc))
	if err != nil {
		return nil, err
	}

	ipkt_data_sig_enc, err := enc_AES_256_CTR(p.enc_key_inner_pkt_sig, iv, ipkt_data_sig)
	if err != nil {
		return nil, err
	}

	opkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "open",
			Open: base64.StdEncoding.EncodeToString(p.public_line_key.ecc_pubkey_enc),
			Sig:  base64.StdEncoding.EncodeToString(ipkt_data_sig_enc),
			Iv:   hex.EncodeToString(iv),
		},
		body: ipkt_data_enc,
	}

	return opkt, nil
}

func decompose_open_pkt(local *rsa.PrivateKey, opkt *pkt_t) (*public_line_key, error) {
	if opkt.hdr.Type != "open" {
		return nil, errInvalidPkt
	}

	iv, err := hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("open: invalid iv")
	}

	ipkt_data_sig_enc, err := base64.StdEncoding.DecodeString(opkt.hdr.Sig)
	if err != nil {
		return nil, err
	}

	ipkt_data_enc := opkt.body

	ecc_pubkey_enc, err := base64.StdEncoding.DecodeString(opkt.hdr.Open)
	if err != nil {
		return nil, err
	}

	ecc_pubkey_data, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, local, ecc_pubkey_enc, nil)
	if err != nil {
		return nil, err
	}

	var ecc_pubkey *ecdh.PublicKey
	{
		x, y := elliptic.Unmarshal(elliptic.P256(), ecc_pubkey_data)
		ecc_pubkey = &ecdh.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}

	enc_key_inner_pkt := hash_SHA256(ecc_pubkey_data)

	ipkt_data, err := dec_AES_256_CTR(enc_key_inner_pkt, iv, ipkt_data_enc)
	if err != nil {
		return nil, err
	}

	ipkt, err := parse_pkt(ipkt_data, opkt.peer, opkt.netpath)
	if err != nil {
		return nil, err
	}

	hex_line_id := ipkt.hdr.Line
	to_hashname_hex := ipkt.hdr.To
	rsa_pubkey_der := ipkt.body
	at := time.Unix(ipkt.hdr.At/1000, ipkt.hdr.At%1000*1000000)

	to_hashname, err := HashnameFromString(to_hashname_hex)
	if err != nil {
		return nil, err
	}

	bin_line_id, err := hex.DecodeString(ipkt.hdr.Line)
	if err != nil {
		return nil, err
	}
	if len(bin_line_id) != 16 {
		return nil, errors.New("open: invalid line_id")
	}

	rsa_pubkey, err := dec_DER_RSA(rsa_pubkey_der)
	if err != nil {
		return nil, err
	}

	hashname, err := HashnameFromPublicKey(rsa_pubkey)
	if err != nil {
		return nil, err
	}

	enc_key_inner_pkt_sig := hash_SHA256(ecc_pubkey_data, bin_line_id)

	ipkt_data_sig, err := dec_AES_256_CTR(enc_key_inner_pkt_sig, iv, ipkt_data_sig_enc)
	if err != nil {
		return nil, err
	}

	err = rsa.VerifyPKCS1v15(rsa_pubkey, crypto.SHA256, hash_SHA256(ipkt_data_enc), ipkt_data_sig)
	if err != nil {
		return nil, err
	}

	pub := &public_line_key{
		hashname:       hashname,
		id:             hex_line_id,
		rsa_pubkey:     rsa_pubkey,
		ecc_pubkey:     ecc_pubkey,
		ecc_pubkey_enc: ecc_pubkey_enc,
		to:             to_hashname,
		at:             at,
	}

	return pub, nil
}

func (pub *public_line_key) verify(other *public_line_key, self Hashname) error {
	if self != pub.to {
		return errors.New("hashname mismatch")
	}

	if other != nil {
		if !pub.at.After(other.at) {
			return errors.New("stale public line half")
		}
	}

	return nil
}

func line_activate(prv *private_line_key, pub *public_line_key) (*shared_line_key, error) {
	shared_key, err := prv.ecc_prvkey.GenerateShared(pub.ecc_pubkey, ecdh.MaxSharedKeyLength(pub.ecc_pubkey))
	if err != nil {
		return nil, err
	}

	snd_id, err := hex.DecodeString(pub.id)
	if err != nil {
		return nil, err
	}

	rcv_id, err := hex.DecodeString(prv.id)
	if err != nil {
		return nil, err
	}

	enc_key := hash_SHA256(shared_key, rcv_id, snd_id)
	dec_key := hash_SHA256(shared_key, snd_id, rcv_id)

	return &shared_line_key{
		prv_half: prv,
		pub_half: pub,
		enc_key:  enc_key,
		dec_key:  dec_key,
	}, nil
}

func (l *shared_line_key) enc(i *pkt_t) (*pkt_t, error) {
	ipkt_data, err := i.format_pkt()
	if err != nil {
		return nil, err
	}

	iv, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	ipkt_data_enc, err := enc_AES_256_CTR(l.enc_key, iv, ipkt_data)
	if err != nil {
		return nil, err
	}

	o := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "line",
			Line: l.pub_half.id,
			Iv:   hex.EncodeToString(iv),
		},
		body:    ipkt_data_enc,
		peer:    i.peer,
		netpath: i.netpath,
	}

	return o, nil
}

func (l *shared_line_key) dec(i *pkt_t) (*pkt_t, error) {
	if i.hdr.Type != "line" {
		return nil, errInvalidPkt
	}

	iv, err := hex.DecodeString(i.hdr.Iv)
	if err != nil {
		return nil, errInvalidPkt
	}
	if len(iv) != 16 {
		return nil, errInvalidPkt
	}

	ipkt_data, err := dec_AES_256_CTR(l.dec_key, iv, i.body)
	if err != nil {
		return nil, errInvalidPkt
	}

	ipkt, err := parse_pkt(ipkt_data, i.peer, i.netpath)
	if err != nil {
		return nil, errInvalidPkt
	}

	return ipkt, nil
}

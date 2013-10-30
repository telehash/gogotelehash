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

type pkt_open struct {
	Type string `json:"type"`
	Open string `json:"open"`
	Iv   string `json:"iv"`
	Sig  string `json:"sig"`
}

type pkt_open_inner struct {
	To     string `json:"to"`
	At     int64  `json:"at"`
	Line   string `json:"line"`
	Family string `json:"family,omitempty"`
}

// Outbound open packet
type cmd_open_o struct {
	peer  *peer_t
	reply chan error
}

func (cmd *cmd_open_o) log_err(err error) {
	cmd.reply <- err
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-generation
func (cmd *cmd_open_o) exec(s *Switch) error {
	var (
		err        error
		ecprv      *ecdh.PrivateKey
		ecpub_data []byte
		rsapub_der []byte
		inner_pkt  []byte
		inner_sig  []byte
		outer_sig  []byte
		open       []byte
		pkt        []byte
		line       *line_t
		iv         []byte
		line_id    []byte
	)

	line = s.i_open[cmd.peer.hashname]
	if line == nil {
		line = &line_t{_switch: s}
	}
	line.peer = cmd.peer

	{ // STEP 2:
		// - Generate an IV and a line identifier from a secure random source, both
		//   16 bytes
		iv, err = make_rand(16)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
		line_id, err = make_rand(16)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 3:
		// - Generate a new elliptic curve keypair, based on the "nistp256" curve
		ecprv, err = ecdh.GenerateKey(rand.Reader, elliptic.P256())
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 4:
		// - SHA-256 hash the public elliptic key to form the encryption key for the
		//   inner packet
		ecpub_data, err = ecprv.PublicKey.Marshal()
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 5:
		// - Form the inner packet containing a current timestamp at, line identifier,
		//   recipient hashname, and family (if you have such a value). Your own RSA
		rsapub_der, err = enc_DER_RSA(&s.identity.PublicKey)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
		line.at = time.Now()
		inner_pkt, err = form_packet(pkt_open_inner{
			To:   cmd.peer.hashname,
			At:   line.at.Unix(),
			Line: hex.EncodeToString(line_id),
		}, rsapub_der)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 6:
		// - Encrypt the inner packet using the hashed public elliptic key from #4 and
		//   the IV you generated at #2 using AES-256-CTR.
		inner_pkt, err = enc_AES_256_CTR(hash_SHA256(ecpub_data), iv, inner_pkt)
	}

	{ // STEP 7:
		// - Create a signature from the encrypted inner packet using your own RSA
		//   keypair, a SHA 256 digest, and PKCSv1.5 padding
		inner_sig, err = rsa.SignPKCS1v15(rand.Reader, s.identity, crypto.SHA256, hash_SHA256(inner_pkt))
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 7.i:
		// - Encrypt the signature using a new AES-256-CTR cipher with the same IV and
		//   a new SHA-256 key hashed from the public elliptic key + the line value
		//   (16 bytes from #5), then base64 encode the result as the value for the
		//   sig param.
		outer_sig, err = enc_AES_256_CTR(hash_SHA256(ecpub_data, line_id), iv, inner_sig)
	}

	{ // STEP 8:
		// - Create an open param, by encrypting the public elliptic curve key you
		//   generated (in uncompressed form, aka ANSI X9.63) with the recipient's
		//   RSA public key and OAEP padding.
		open, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, cmd.peer.pubkey, ecpub_data, nil)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	{ // STEP 9:
		// - Form the outer packet containing the open type, open param, the generated
		//   iv, and the sig value.
		pkt, err = form_packet(pkt_open{
			Type: "open",
			Open: base64.StdEncoding.EncodeToString(open),
			Sig:  base64.StdEncoding.EncodeToString(outer_sig),
			Iv:   hex.EncodeToString(iv),
		}, inner_pkt)
		if err != nil {
			cmd.log_err(err)
			return nil
		}
	}

	line.LineOut = line_id
	line.local_eckey = ecprv

	// Send packet pkt
	s.o_open[cmd.peer.hashname] = line
	s.o_queue <- pkt_udp_t{cmd.peer.addr, pkt}

	close(cmd.reply)
	return nil
}

// Inbound open packet
type cmd_open_i struct {
	pkt pkt_udp_t
}

func (cmd *cmd_open_i) log_err(err error) {
	Log.Debugf("open(i) error: %s", err)
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-processing-1
func (cmd *cmd_open_i) exec(s *Switch) error {
	var (
		data       = cmd.pkt.data
		err        error
		outer_pkt  pkt_open
		inner_pkt  pkt_open_inner
		iv         []byte
		line_id    []byte
		line       *line_t
		sig        []byte
		hashname   string
		ecpub_data []byte
		ecpub_key  *ecdh.PublicKey
		rsapub_key *rsa.PublicKey
		aes_key_1  []byte
		aes_key_2  []byte
		at         time.Time
		now        time.Time
		icmd       command_i
		outer_body = make([]byte, 1500)
		inner_body = make([]byte, 1500)
	)

	// decode the packet
	outer_body, err = parse_packet(data, &outer_pkt, outer_body)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	if outer_pkt.Type != "open" {
		cmd.log_err(errors.New("open: type is not `open`"))
		return nil // drop
	}

	// decode IV
	iv, err = hex.DecodeString(outer_pkt.Iv)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// decode Sig
	sig, err = base64.StdEncoding.DecodeString(outer_pkt.Sig)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// STEP 1:
	// - Using your private key and OAEP padding, decrypt the open param,
	//   extracting the ECC public key (in uncompressed form) of the sender
	ecpub_data, err = base64.StdEncoding.DecodeString(outer_pkt.Open)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}
	ecpub_data, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, s.identity, ecpub_data, nil)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}
	ecpub_key, err = ecdh.UnmarshalPublic(ecpub_data)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// STEP 2:
	// - Hash the ECC public key with SHA-256 to generate an AES key
	aes_key_1 = hash_SHA256(ecpub_data)

	// STEP 3:
	// - Decrypt the inner packet using the generated key and IV value with the
	//   AES-256-CTR algorithm.
	data, err = dec_AES_256_CTR(aes_key_1, iv, outer_body)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// parse inner pkt
	inner_body, err = parse_packet(data, &inner_pkt, inner_body[:0])
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// decode Line
	line_id, err = hex.DecodeString(inner_pkt.Line)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// STEP 4:
	// - Verify the to value of the inner packet matches your hashname
	if inner_pkt.To != s.hashname {
		cmd.log_err(errors.New("open: hashname mismatch"))
		return nil // drop
	}

	// STEP 5:
	// - Extract the RSA public key of the sender from the inner packet BODY
	//   (binary DER format)
	rsapub_key, err = dec_DER_RSA(inner_body)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// STEP 6:
	// - SHA-256 hash the RSA public key to derive the sender's hashname
	hashname = hex.EncodeToString(hash_SHA256(inner_body))

	// STEP 7:
	// - Verify the at timestamp is both within a reasonable amount of time to
	//   account for network delays and clock skew, and is newer than any other
	//   'open' requests received from the sender.
	at = time.Unix(inner_pkt.At, 0)
	now = time.Now()
	if at.Before(now.Add(-s.open_delta)) || at.After(now.Add(s.open_delta)) {
		cmd.log_err(errors.New("open: open.at is too far of"))
		return nil // drop
	}
	if line := s.i_open[hashname]; line != nil && line.at.After(at) {
		cmd.log_err(errors.New("open: open.at is older than another line"))
		return nil // drop
	}
	line = s.o_open[hashname]
	if line == nil {
		line = &line_t{_switch: s}
		s.i_open[hashname] = line
	}

	// STEP 8:
	// - SHA-256 hash the ECC public key with the 16 bytes derived from the inner
	//   line hex value to generate an new AES key
	aes_key_2 = hash_SHA256(ecpub_data, line_id)

	// STEP 9:
	// - Decrypt the outer packet sig value using AES-256-CTR with the key from #8
	//   and the same IV value as #3.
	sig, err = dec_AES_256_CTR(aes_key_2, iv, sig)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// STEP 10:
	// - Using the RSA public key of the sender, verify the signature (decrypted
	//   in #9) of the original (encrypted) form of the inner packet
	err = rsa.VerifyPKCS1v15(rsapub_key, crypto.SHA256, hash_SHA256(outer_body), sig)
	if err != nil {
		cmd.log_err(err)
		return nil // drop
	}

	// ====> Open packet is now verified <========================================

	line.remote_eckey = ecpub_key
	line.LineIn = line_id

	// STEP 11:
	// - If an open packet has not already been sent to this hashname, do so by
	//   creating one following the steps above
	if !line.can_activate() {
		s.known_peers[hashname] = &peer_t{hashname, cmd.pkt.addr, rsapub_key}

		reply := make(chan error, 1)
		icmd = &cmd_open_o{s.known_peers[hashname], reply}
		err = icmd.exec(s)
		if err != nil {
			cmd.log_err(err)
			return nil // drop
		}
		err = <-reply
		if err != nil {
			cmd.log_err(err)
			return nil // drop
		}
	}

	// STEP 12:
	// - After sending your own open packet in response, you may now generate a
	//   line shared secret using the received and sent ECC public keys and
	//   Elliptic Curve Diffie-Hellman (ECDH).
	if line.can_activate() {
		err = line.activate()
		if err != nil {
			cmd.log_err(err)
			return nil // drop
		}
	}

	return nil
}

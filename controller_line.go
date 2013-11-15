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
	"github.com/fd/go-util/log"
	"github.com/gokyle/ecdh"

	"sync"
	"time"
)

type line_controller struct {
	sw            *Switch
	peering_lines map[Hashname]bool    // hashname -> bool
	opening_lines map[Hashname]*line_t // hashname -> line
	rcv_lines     map[string]*line_t   // line id  -> linex
	max_time_skew time.Duration
	mtx           sync.RWMutex
	cnd           *sync.Cond
	log           log.Logger
}

func line_controller_open(sw *Switch) (*line_controller, error) {

	h := &line_controller{
		sw:            sw,
		peering_lines: make(map[Hashname]bool),
		opening_lines: make(map[Hashname]*line_t),
		rcv_lines:     make(map[string]*line_t),
		max_time_skew: 5 * time.Second,
		log:           sw.log.Sub(log.INFO, "lines"),
	}

	h.cnd = sync.NewCond(h.mtx.RLocker())

	return h, nil
}

func (h *line_controller) rcv_pkt(outer_pkt *pkt_t) error {
	switch outer_pkt.hdr.Type {

	case "open":
		return h._rcv_open_pkt(outer_pkt)

	case "line":
		return h._rcv_line_pkt(outer_pkt)

	default:
		// h.log.Debugf("rcv pkt err=%s pkt=%#v", errInvalidPkt, outer_pkt)
		return errInvalidPkt

	}
}

func (h *line_controller) _rcv_line_pkt(opkt *pkt_t) error {
	line := h._get_rcv_line(opkt.hdr.Line)
	if line == nil {
		return errUnknownLine
	}

	return line.rcv_pkt(opkt)
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-generation
func (h *line_controller) _snd_open_pkt(peer *peer_t) error {
	var (
		err        error
		ecc_prvkey *ecdh.PrivateKey
		ecc_pubkey []byte
		rsapub_der []byte
		inner_pkt  []byte
		inner_sig  []byte
		outer_sig  []byte
		open       []byte
		line       *line_t
		iv         []byte
		line_id    []byte
	)
	if peer == nil {
		h.log.Debugf("line: open err=%s", "unknown peer")
		return errInvalidOpenReq
	}

	if peer.addr.hashname.IsZero() {
		h.log.Debugf("line: open err=%s", "unknown peer (missing hashname)")
		return errInvalidOpenReq
	}

	if peer.addr.addr == nil {
		h.log.Debugf("line: open err=%s", "unknown peer (missing address)")
		return errInvalidOpenReq
	}

	if peer.addr.pubkey == nil {
		return errMissingPublicKey
	}

	{ // guarded section
		h.mtx.Lock()

		// check if line is already opening
		line = h.opening_lines[peer.addr.hashname]
		if line != nil {
			h.mtx.Unlock()
			return nil
		}

		// make new line
		line_id, err = make_rand(16)
		if err != nil {
			h.mtx.Unlock()
			return err
		}

		line = make_line(h.sw, peer, hex.EncodeToString(line_id))

		// put in opening register _rcv_open_pkt() will activate the line later
		h.opening_lines[peer.addr.hashname] = line
		h.rcv_lines[line.rcv_id] = line
		line.touch(true)

		h.mtx.Unlock()
	}

	{ // STEP 2:
		// - Generate an IV and a line identifier from a secure random source, both
		//   16 bytes
		iv, err = make_rand(16)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 3:
		// - Generate a new elliptic curve keypair, based on the "nistp256" curve
		ecc_prvkey, err = ecdh.GenerateKey(rand.Reader, elliptic.P256())
		if err != nil {
			h._drop_line(line, err)
			return err
		}
		line.ecc_prvkey = ecc_prvkey
	}

	{ // STEP 4:
		// - SHA-256 hash the public elliptic key to form the encryption key for the
		//   inner packet
		ecc_pubkey, err = ecc_prvkey.PublicKey.Marshal()
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 5:
		// - Form the inner packet containing a current timestamp at, line identifier,
		//   recipient hashname, and family (if you have such a value). Your own RSA
		rsapub_der, err = enc_DER_RSA(&h.sw.key.PublicKey)
		if err != nil {
			h._drop_line(line, err)
			return err
		}

		line.snd_at = time.Now()

		pkt := pkt_t{
			hdr: pkt_hdr_t{
				To:   line.peer.addr.hashname.String(),
				At:   line.snd_at.Unix(),
				Line: line.rcv_id,
			},
			body: rsapub_der,
		}

		inner_pkt, err = pkt.format_pkt()
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 6:
		// - Encrypt the inner packet using the hashed public elliptic key from #4 and
		//   the IV you generated at #2 using AES-256-CTR.
		inner_pkt, err = enc_AES_256_CTR(hash_SHA256(ecc_pubkey), iv, inner_pkt)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 7:
		// - Create a signature from the encrypted inner packet using your own RSA
		//   keypair, a SHA 256 digest, and PKCSv1.5 padding
		inner_sig, err = rsa.SignPKCS1v15(rand.Reader, h.sw.key, crypto.SHA256, hash_SHA256(inner_pkt))
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 7.i:
		// - Encrypt the signature using a new AES-256-CTR cipher with the same IV and
		//   a new SHA-256 key hashed from the public elliptic key + the line value
		//   (16 bytes from #5), then base64 encode the result as the value for the
		//   sig param.
		outer_sig, err = enc_AES_256_CTR(hash_SHA256(ecc_pubkey, line_id), iv, inner_sig)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 8:
		// - Create an open param, by encrypting the public elliptic curve key you
		//   generated (in uncompressed form, aka ANSI X9.63) with the recipient's
		//   RSA public key and OAEP padding.
		open, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, line.peer.addr.pubkey, ecc_pubkey, nil)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	{ // STEP 9:
		// - Form the outer packet containing the open type, open param, the generated
		//   iv, and the sig value.
		opkt := pkt_t{
			hdr: pkt_hdr_t{
				Type: "open",
				Open: base64.StdEncoding.EncodeToString(open),
				Sig:  base64.StdEncoding.EncodeToString(outer_sig),
				Iv:   hex.EncodeToString(iv),
			},
			body: inner_pkt,
			addr: line.peer.addr,
		}

		err = h.sw.net.snd_pkt(&opkt)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	return nil
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-processing-1
func (h *line_controller) _rcv_open_pkt(opkt *pkt_t) error {
	var (
		ipkt            *pkt_t
		err             error
		data            []byte
		iv              []byte
		line_id         []byte
		line            *line_t
		sig             []byte
		hashname        Hashname
		ecc_pubkey_data []byte
		ecc_pubkey      *ecdh.PublicKey
		rsa_pubkey      *rsa.PublicKey
		aes_key_1       []byte
		aes_key_2       []byte
		at              time.Time
		now             = time.Now()
	)

	if opkt.hdr.Type != "open" {
		return errors.New("open: type is not `open`")
	}

	// decode IV
	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		return err
	}
	if len(iv) != 16 {
		return errors.New("open: invalid iv")
	}

	// decode Sig
	sig, err = base64.StdEncoding.DecodeString(opkt.hdr.Sig)
	if err != nil {
		return err
	}

	// STEP 1:
	// - Using your private key and OAEP padding, decrypt the open param,
	//   extracting the ECC public key (in uncompressed form) of the sender
	ecc_pubkey_data, err = base64.StdEncoding.DecodeString(opkt.hdr.Open)
	if err != nil {
		return err
	}
	ecc_pubkey_data, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, h.sw.key, ecc_pubkey_data, nil)
	if err != nil {
		return err
	}
	ecc_pubkey, err = ecdh.UnmarshalPublic(ecc_pubkey_data)
	if err != nil {
		return err
	}

	// STEP 2:
	// - Hash the ECC public key with SHA-256 to generate an AES key
	aes_key_1 = hash_SHA256(ecc_pubkey_data)

	// STEP 3:
	// - Decrypt the inner packet using the generated key and IV value with the
	//   AES-256-CTR algorithm.
	data, err = dec_AES_256_CTR(aes_key_1, iv, opkt.body)
	if err != nil {
		return err
	}

	// parse inner pkt
	ipkt, err = parse_pkt(data, opkt.addr)
	if err != nil {
		return err
	}

	// decode Line
	line_id, err = hex.DecodeString(ipkt.hdr.Line)
	if err != nil {
		return err
	}
	if len(line_id) != 16 {
		return errors.New("open: invalid line_id")
	}

	// STEP 4:
	// - Verify the to value of the inner packet matches your hashname
	if ipkt.hdr.To != h.sw.peers.get_local_hashname().String() {
		return errors.New("open: hashname mismatch")
	}

	// STEP 5:
	// - Extract the RSA public key of the sender from the inner packet BODY
	//   (binary DER format)
	rsa_pubkey, err = dec_DER_RSA(ipkt.body)
	if err != nil {
		return err
	}

	// STEP 6:
	// - SHA-256 hash the RSA public key to derive the sender's hashname
	hashname, err = HashnameFromBytes(hash_SHA256(ipkt.body))
	if err != nil {
		return err
	}

	// STEP 7:
	// - Verify the at timestamp is both within a reasonable amount of time to
	//   account for network delays and clock skew, and is newer than any other
	//   'open' requests received from the sender.
	at = time.Unix(ipkt.hdr.At, 0)
	if at.Before(now.Add(-h.max_time_skew)) || at.After(now.Add(h.max_time_skew)) {
		return errors.New("open: open.at is too far of")
	}

	{ // guarded section
		h.mtx.RLock()

		if line := h.opening_lines[hashname]; line != nil && line.rcv_at.After(at) {
			h.mtx.RUnlock()
			return errors.New("open: open.rcv_at is older than another line")
		}

		h.mtx.RUnlock()
	}

	// STEP 8:
	// - SHA-256 hash the ECC public key with the 16 bytes derived from the inner
	//   line hex value to generate an new AES key
	aes_key_2 = hash_SHA256(ecc_pubkey_data, line_id)

	// STEP 9:
	// - Decrypt the outer packet sig value using AES-256-CTR with the key from #8
	//   and the same IV value as #3.
	sig, err = dec_AES_256_CTR(aes_key_2, iv, sig)
	if err != nil {
		return err
	}

	// STEP 10:
	// - Using the RSA public key of the sender, verify the signature (decrypted
	//   in #9) of the original (encrypted) form of the inner packet
	err = rsa.VerifyPKCS1v15(rsa_pubkey, crypto.SHA256, hash_SHA256(opkt.body), sig)
	if err != nil {
		return err
	}

	// ====> Open packet is now verified <========================================

	// Update the peer data if nececery
	addr, err := make_addr(hashname, ZeroHashname, opkt.addr.addr.String(), rsa_pubkey)
	if err != nil {
		return err
	}

	peer, _ := h.sw.peers.add_peer(addr)

	// STEP 11:
	// - If an open packet has not already been sent to this hashname, do so by
	//   creating one following the steps above
	//
	{ // guarded section
		h.mtx.RLock()
		line = h.opening_lines[hashname]
		h.mtx.RUnlock()
	}
	if line == nil {
		err = h._snd_open_pkt(peer)
		if err != nil {
			return err // drop
		}

		{ // guarded section
			h.mtx.RLock()
			line = h.opening_lines[hashname]
			h.mtx.RUnlock()
		}
	}

	line.peer = peer
	line.snd_id = hex.EncodeToString(line_id)
	line.ecc_pubkey = ecc_pubkey

	// ====> Line is now in opening state <=======================================

	// STEP 12:
	// - After sending your own open packet in response, you may now generate a
	//   line shared secret using the received and sent ECC public keys and
	//   Elliptic Curve Diffie-Hellman (ECDH).
	shared_key, err := line.ecc_prvkey.GenerateShared(line.ecc_pubkey, ecdh.MaxSharedKeyLength(line.ecc_pubkey))
	if err != nil {
		h._drop_line(line, err)
		return err // drop
	}

	snd_id, err := hex.DecodeString(line.snd_id)
	if err != nil {
		h._drop_line(line, err)
		return err // drop
	}

	rcv_id, err := hex.DecodeString(line.rcv_id)
	if err != nil {
		h._drop_line(line, err)
		return err // drop
	}

	line.enc_key = hash_SHA256(shared_key, rcv_id, snd_id)
	line.dec_key = hash_SHA256(shared_key, snd_id, rcv_id)

	// activate line and notify waiters
	{ //guarded section
		h.mtx.Lock()

		line.ecc_prvkey = nil
		line.ecc_pubkey = nil

		delete(h.peering_lines, line.peer.addr.hashname)
		delete(h.opening_lines, line.peer.addr.hashname)
		peer.activate_line(line)

		h.rcv_lines[line.rcv_id] = line

		h.cnd.Broadcast()
		h.mtx.Unlock()

		// handle buffered line packets
		line.mtx.Lock()
		buf := line.rcv_buf
		line.rcv_buf = nil
		line.mtx.Unlock()

		for _, opkt := range buf {
			err := line.rcv_pkt(opkt)
			if err != nil {
				h.log.Debugf("rcv buffer line packet err=%s", err)
			}
		}
	}

	h.log.Infof("line opened: %s:%s (%s -> %s)",
		short_hash(line.rcv_id),
		short_hash(line.snd_id),
		h.sw.peers.get_local_hashname().Short(),
		line.peer.addr.hashname.Short())

	return nil
}

func (h *line_controller) _drop_line(line *line_t, err error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	delete(h.peering_lines, line.peer.addr.hashname)
	delete(h.opening_lines, line.peer.addr.hashname)
	delete(h.rcv_lines, line.rcv_id)
	line.peer.deactivate_line(line)
	h.cnd.Broadcast()
}

func (h *line_controller) _get_rcv_line(id string) *line_t {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.rcv_lines[id]
}

func (h *line_controller) tick(now time.Time) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// if there was no activity on a line in the last 15 seconds
	deadline := now.Add(-60 * time.Second)

	for _, line := range h.rcv_lines {

		if line.get_last_activity().Before(deadline) {

			line.peer.deactivate_line(line)
			delete(h.rcv_lines, line.rcv_id)

			h.log.Infof("line closed: %s:%s (%s -> %s)",
				short_hash(line.rcv_id),
				short_hash(line.snd_id),
				h.sw.peers.get_local_hashname().Short(),
				line.peer.addr.hashname.Short())

			continue
		}

		if line.get_last_rcv().Before(deadline) {

			line.peer.deactivate_line(line)
			delete(h.rcv_lines, line.rcv_id)

			line.peer.mark_as_broken()

			h.log.Infof("line broken: %s:%s (%s -> %s)",
				short_hash(line.rcv_id),
				short_hash(line.snd_id),
				h.sw.peers.get_local_hashname().Short(),
				line.peer.addr.hashname.Short())

			continue
		}
	}
}

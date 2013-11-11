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
	"net"
	"sync"
	"time"
)

type line_t struct {
	hashname   Hashname         // hashname of target
	pubkey     *rsa.PublicKey   // rsa pubkey of target (non-nil during open phase)
	ecc_prvkey *ecdh.PrivateKey // (non-nil during open phase)
	ecc_pubkey *ecdh.PublicKey  // (non-nil during open phase)
	addr       *net.UDPAddr     // address of target
	snd_id     string           // line id used when sending packets
	rcv_id     string           // line id used when receiving packets
	snd_at     time.Time        // when the line was opened on the local side
	rcv_at     time.Time        // when the line was opened on the remote side
	enc_key    []byte           // aes key used when sending packets
	dec_key    []byte           // aes key  used when receiving packets
	// last_activity time.Time
	// mtx           sync.RWMutex
}

type line_controller struct {
	sw            *Switch
	opening_lines map[Hashname]*line_t // hashname -> line
	snd_lines     map[Hashname]*line_t // hashname -> line
	rcv_lines     map[string]*line_t   // line id  -> linex
	max_time_skew time.Duration
	mtx           sync.RWMutex
	cnd           *sync.Cond
}

func line_controller_open(sw *Switch) (*line_controller, error) {

	h := &line_controller{
		sw:            sw,
		snd_lines:     make(map[Hashname]*line_t),
		opening_lines: make(map[Hashname]*line_t),
		rcv_lines:     make(map[string]*line_t),
		max_time_skew: 5 * time.Second,
	}

	h.cnd = sync.NewCond(h.mtx.RLocker())

	return h, nil
}

func (h *line_controller) rcv_pkt(outer_pkt *pkt_t) (*pkt_t, error) {
	switch outer_pkt.hdr.Type {

	case "open":
		return h._rcv_open_pkt(outer_pkt)

	case "line":
		return h._rcv_line_pkt(outer_pkt)

	default:
		return nil, errInvalidPkt

	}
}

func (h *line_controller) snd_pkt(to Hashname, pkt *pkt_t) (*pkt_t, error) {
	switch pkt.hdr.Type {

	case "+ping": // NAT breaker
		return pkt, nil

	case "open":
		return pkt, nil

	default: // is outer packet
		return h._snd_line_pkt(to, pkt)

	}
}

func (h *line_controller) has_open_line_to(hn Hashname) bool {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.snd_lines[hn] != nil
}

// Send a packet over a line.
// This function will wrap the packet in a line packet.
func (h *line_controller) _snd_line_pkt(to Hashname, ipkt *pkt_t) (*pkt_t, error) {

	// get an open line; open one if necessary
	line, err := h._get_snd_line(to)
	if err != nil {
		return nil, err
	}

	ipkt_data, err := ipkt.format_pkt()
	if err != nil {
		return nil, err
	}

	iv, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	ipkt_data, err = enc_AES_256_CTR(line.enc_key, iv, ipkt_data)
	if err != nil {
		return nil, err
	}

	opkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "line",
			Line: line.snd_id,
			Iv:   hex.EncodeToString(iv),
		},
		body: ipkt_data,
		addr: line.addr,
	}

	return opkt, nil
}

func (h *line_controller) _rcv_line_pkt(opkt *pkt_t) (*pkt_t, error) {
	var (
		line *line_t
		ipkt *pkt_t
		iv   []byte
		err  error
	)

	if opkt.hdr.Type != "line" {
		return nil, errInvalidPkt
	}

	line = h._get_rcv_line(opkt.hdr.Line)
	if line == nil {
		return nil, errUnknownLine
	}

	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		return nil, errInvalidPkt
	}

	opkt.body, err = dec_AES_256_CTR(line.dec_key, iv, opkt.body)
	if err != nil {
		return nil, errInvalidPkt
	}

	ipkt, err = parse_pkt(opkt.body, opkt.addr)
	if err != nil {
		return nil, errInvalidPkt
	}

	ipkt.peer = line.hashname

	return ipkt, nil
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-generation
func (h *line_controller) _snd_open_pkt(to Hashname) error {
	var (
		peer       *peer_t
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

	peer = h.sw.peers.get_peer(to)
	if peer == nil {
		return errInvalidOpenReq
	}

	if peer.hashname.IsZero() {
		return errInvalidOpenReq
	}

	if peer.addr == nil {
		return errInvalidOpenReq
	}

	if peer.pubkey == nil {
		return errMissingPublicKey
	}

	{ // guarded section
		h.mtx.Lock()

		// check if line is already opened
		line = h.snd_lines[peer.hashname]
		if line != nil {
			h.mtx.Unlock()
			return nil
		}

		// check if line is already opening
		line = h.opening_lines[peer.hashname]
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

		line = &line_t{
			hashname: peer.hashname,
			pubkey:   peer.pubkey,
			addr:     peer.addr,
			snd_id:   hex.EncodeToString(line_id),
		}

		// put in opening register _rcv_open_pkt() will activate the line later
		h.opening_lines[peer.hashname] = line

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
				To:   line.hashname.String(),
				At:   line.snd_at.Unix(),
				Line: line.snd_id,
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
		open, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, line.pubkey, ecc_pubkey, nil)
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
			addr: line.addr,
		}

		err = h.sw.net.snd_pkt(to, &opkt)
		if err != nil {
			h._drop_line(line, err)
			return err
		}
	}

	return nil
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-processing-1
func (h *line_controller) _rcv_open_pkt(opkt *pkt_t) (*pkt_t, error) {
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
		return nil, errors.New("open: type is not `open`")
	}

	// decode IV
	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		return nil, err
	}
	if len(iv) != 16 {
		return nil, errors.New("open: invalid iv")
	}

	// decode Sig
	sig, err = base64.StdEncoding.DecodeString(opkt.hdr.Sig)
	if err != nil {
		return nil, err
	}

	// STEP 1:
	// - Using your private key and OAEP padding, decrypt the open param,
	//   extracting the ECC public key (in uncompressed form) of the sender
	ecc_pubkey_data, err = base64.StdEncoding.DecodeString(opkt.hdr.Open)
	if err != nil {
		return nil, err
	}
	ecc_pubkey_data, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, h.sw.key, ecc_pubkey_data, nil)
	if err != nil {
		return nil, err
	}
	ecc_pubkey, err = ecdh.UnmarshalPublic(ecc_pubkey_data)
	if err != nil {
		return nil, err
	}

	// STEP 2:
	// - Hash the ECC public key with SHA-256 to generate an AES key
	aes_key_1 = hash_SHA256(ecc_pubkey_data)

	// STEP 3:
	// - Decrypt the inner packet using the generated key and IV value with the
	//   AES-256-CTR algorithm.
	data, err = dec_AES_256_CTR(aes_key_1, iv, opkt.body)
	if err != nil {
		return nil, err
	}

	// parse inner pkt
	ipkt, err = parse_pkt(data, opkt.addr)
	if err != nil {
		return nil, err
	}

	// decode Line
	line_id, err = hex.DecodeString(ipkt.hdr.Line)
	if err != nil {
		return nil, err
	}
	if len(line_id) != 16 {
		return nil, errors.New("open: invalid line_id")
	}

	// STEP 4:
	// - Verify the to value of the inner packet matches your hashname
	if ipkt.hdr.To != h.sw.peers.get_local_hashname().String() {
		return nil, errors.New("open: hashname mismatch")
	}

	// STEP 5:
	// - Extract the RSA public key of the sender from the inner packet BODY
	//   (binary DER format)
	rsa_pubkey, err = dec_DER_RSA(ipkt.body)
	if err != nil {
		return nil, err
	}

	// STEP 6:
	// - SHA-256 hash the RSA public key to derive the sender's hashname
	hashname, err = HashnameFromBytes(hash_SHA256(ipkt.body))
	if err != nil {
		return nil, err
	}

	// STEP 7:
	// - Verify the at timestamp is both within a reasonable amount of time to
	//   account for network delays and clock skew, and is newer than any other
	//   'open' requests received from the sender.
	at = time.Unix(ipkt.hdr.At, 0)
	if at.Before(now.Add(-h.max_time_skew)) || at.After(now.Add(h.max_time_skew)) {
		return nil, errors.New("open: open.at is too far of")
	}

	{ // guarded section
		h.mtx.RLock()

		if line := h.snd_lines[hashname]; line != nil && line.rcv_at.After(at) {
			h.mtx.RUnlock()
			return nil, errors.New("open: open.rcv_at is older than another line")
		}

		if line := h.opening_lines[hashname]; line != nil && line.rcv_at.After(at) {
			h.mtx.RUnlock()
			return nil, errors.New("open: open.rcv_at is older than another line")
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
		return nil, err
	}

	// STEP 10:
	// - Using the RSA public key of the sender, verify the signature (decrypted
	//   in #9) of the original (encrypted) form of the inner packet
	err = rsa.VerifyPKCS1v15(rsa_pubkey, crypto.SHA256, hash_SHA256(opkt.body), sig)
	if err != nil {
		return nil, err
	}

	// ====> Open packet is now verified <========================================

	// Update the peer data if nececery
	h.sw.peers.add_peer(hashname, opkt.addr.String(), rsa_pubkey, ZeroHashname)

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
		err = h._snd_open_pkt(hashname)
		if err != nil {
			return nil, err // drop
		}

		{ // guarded section
			h.mtx.RLock()
			line = h.opening_lines[hashname]
			h.mtx.RUnlock()
		}
	}

	line.rcv_id = hex.EncodeToString(line_id)
	line.ecc_pubkey = ecc_pubkey

	// ====> Line is now in opening state <=======================================

	// STEP 12:
	// - After sending your own open packet in response, you may now generate a
	//   line shared secret using the received and sent ECC public keys and
	//   Elliptic Curve Diffie-Hellman (ECDH).
	shared_key, err := line.ecc_prvkey.GenerateShared(line.ecc_pubkey, ecdh.MaxSharedKeyLength(line.ecc_pubkey))
	if err != nil {
		h._drop_line(line, err)
		return nil, err // drop
	}

	snd_id, err := hex.DecodeString(line.snd_id)
	if err != nil {
		h._drop_line(line, err)
		return nil, err // drop
	}

	rcv_id, err := hex.DecodeString(line.rcv_id)
	if err != nil {
		h._drop_line(line, err)
		return nil, err // drop
	}

	line.enc_key = hash_SHA256(shared_key, snd_id, rcv_id)
	line.dec_key = hash_SHA256(shared_key, rcv_id, snd_id)

	// activate line and notify waiters
	{ //guarded section
		h.mtx.Lock()

		line.pubkey = nil
		line.ecc_prvkey = nil
		line.ecc_pubkey = nil

		delete(h.opening_lines, line.hashname)
		h.snd_lines[line.hashname] = line
		h.rcv_lines[line.rcv_id] = line

		h.cnd.Broadcast()
		h.mtx.Unlock()
	}

	Log.Debugf("line opened: %s:%s (%s -> %s)",
		short_hash(line.rcv_id),
		short_hash(line.snd_id),
		h.sw.peers.get_local_hashname().Short(),
		line.hashname.Short())

	return nil, nil
}

func (h *line_controller) _drop_line(line *line_t, err error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	delete(h.opening_lines, line.hashname)
	delete(h.snd_lines, line.hashname)
	delete(h.rcv_lines, line.rcv_id)
	h.cnd.Broadcast()
}

func (h *line_controller) _get_rcv_line(id string) *line_t {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	return h.rcv_lines[id]
}

func (h *line_controller) _get_snd_line(id Hashname) (*line_t, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	var (
		line *line_t
	)

	line = h.snd_lines[id]
	for line == nil {
		if h.opening_lines[id] == nil {

			h.mtx.RUnlock()
			err := h._snd_open_pkt(id)
			h.mtx.RLock()

			if err != nil {
				return nil, err
			}
		}

		h.cnd.Wait()
		line = h.snd_lines[id]
	}

	return line, nil
}

/*
func (l *line_t) touch() {
  l.mtx.Lock()
  defer l.mtx.Unlock()

  l.last_activity = time.Now()
}

func (l *line_t) get_last_activity() time.Time {
  l.mtx.RLock()
  defer l.mtx.RUnlock()

  return l.last_activity
}

func (h *line_controller) drop_idle_lines() {
  h.lines_mtx.Lock()
  defer h.lines_mtx.Unlock()

  deadline := time.Now().Add(-15 * time.Second)

  for _, line := range h.snd_lines {
    if line.get_last_activity().Before(deadline) {
      delete(h.snd_lines, line.hashname)
      delete(h.rcv_lines, line.rcv_id)
      for _, waiter := range line.waiters {
        waiter <- errors.New("line: closed (idle)")
      }

      Log.Debugf("line closed: %s:%s (%s -> %s)",
        short_hash(line.rcv_id),
        short_hash(line.snd_id),
        h.sw.peers.get_local_hashname().Short(),
        line.hashname.Short())
    }
  }
}
*/

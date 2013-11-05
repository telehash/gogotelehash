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
	"fmt"
	"github.com/gokyle/ecdh"
	"net"
	"sync"
	"time"
)

type line_t struct {
	opened     bool
	hashname   string           // hashname of target
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
	waiters    []chan error     // channels waiting for this line to finish opening
}

type line_handler struct {
	conn          *pkt_handler
	peers         *peer_handler
	key           *rsa.PrivateKey
	snd_lines     map[string]*line_t // hashname -> line
	rcv_lines     map[string]*line_t // line id  -> line
	rcv           chan *pkt_t
	rcv_open      chan *pkt_t
	snd_open      chan line_handler_snd_open
	shutdown      chan bool
	max_time_skew time.Duration
	lines_mtx     sync.RWMutex
}

type line_handler_snd_open struct {
	hashname string
	pubkey   *rsa.PublicKey
	addr     *net.UDPAddr
	reply    chan error
}

func (h *line_handler) reader_loop() {
	defer close(h.rcv)

	for pkt := range h.conn.rcv {

		switch pkt.hdr.Type {
		case "open":
			h.rcv_open <- pkt
		case "line":
			h.rcv_line_pkt(pkt)
		default:
			// Log.Debugf("dropped pkt: unsupported pkt type %q", pkt.hdr.Type)
		}

	}
}

func (h *line_handler) command_loop() {
	for {
		select {

		case <-h.shutdown:
			return

		case pkt := <-h.rcv_open:
			h.rcv_open_pkt(pkt)
		case cmd := <-h.snd_open:
			h.snd_open_pkt(cmd, true)

		}
	}
}

func line_handler_open(addr string, prvkey *rsa.PrivateKey, peers *peer_handler) (*line_handler, error) {
	conn, err := pkt_handler_open(addr)
	if err != nil {
		return nil, err
	}

	h := &line_handler{
		conn:          conn,
		peers:         peers,
		key:           prvkey,
		snd_lines:     make(map[string]*line_t),
		rcv_lines:     make(map[string]*line_t),
		rcv:           make(chan *pkt_t),
		rcv_open:      make(chan *pkt_t),
		snd_open:      make(chan line_handler_snd_open),
		max_time_skew: 5 * time.Second,
		shutdown:      make(chan bool),
	}

	go h.reader_loop()
	go h.command_loop()

	return h, nil
}

func (h *line_handler) close() {
	h.shutdown <- true
	h.conn.close()
}

func (h *line_handler) open_line(hashname string) error {
	peer := h.peers.get_peer(hashname)
	if peer == nil {
		return fmt.Errorf("unknown peer: %s", hashname)
	}

	if peer.pubkey == nil {
		return errMissingPublicKey
	}

	if h.get_snd_line(hashname) != nil {
		return nil
	}

	reply := make(chan error, 1)

	h.snd_open <- line_handler_snd_open{
		hashname: hashname,
		pubkey:   peer.pubkey,
		addr:     peer.addr,
		reply:    reply,
	}

	return <-reply
}

// Send a packet over a line.
// This function will wrap the packet in a line packet.
func (h *line_handler) send(to string, ipkt *pkt_t) error {
	line := h.get_snd_line(to)
	if line == nil {
		err := h.open_line(to)
		if err != nil {
			return err
		}

		line = h.get_snd_line(to)
		if line == nil {
			return errors.New("unknown target: " + to)
		}
	}

	ipkt_data, err := ipkt.format_pkt()
	if err != nil {
		return err
	}

	iv, err := make_rand(16)
	if err != nil {
		return err
	}

	ipkt_data, err = enc_AES_256_CTR(line.enc_key, iv, ipkt_data)
	if err != nil {
		return err
	}

	opkt := pkt_t{
		hdr: pkt_hdr_t{
			Type: "line",
			Line: line.snd_id,
			Iv:   hex.EncodeToString(iv),
		},
		body: ipkt_data,
		addr: line.addr,
	}

	// Log.Debugf("line[%s:%s]: snd %+v", line.snd_id[:8], line.rcv_id[:8], ipkt)
	return h.conn.send(&opkt)
}

func (h *line_handler) rcv_line_pkt(opkt *pkt_t) {
	var (
		line *line_t
		ipkt *pkt_t
		iv   []byte
		err  error
	)

	if opkt.hdr.Type != "line" {
		// Log.Debugf("dropped packet: %+v (error: %s)", opkt, "unexpected pkt type")
		return
	}

	line = h.get_rcv_line(opkt.hdr.Line)
	if line == nil {
		// Log.Debugf("dropped packet: %+v (error: %s)", opkt, "unknown line")
	}

	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		// Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	opkt.body, err = dec_AES_256_CTR(line.dec_key, iv, opkt.body)
	if err != nil {
		// Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	ipkt, err = parse_pkt(opkt.body, opkt.addr)
	if err != nil {
		// Log.Debugf("dropped packet: %+v (error: %s)", opkt, err)
		return
	}

	ipkt.peer = line.hashname

	// Log.Debugf("line[%s:%s]: rcv %+v", line.snd_id[:8], line.rcv_id[:8], ipkt)
	h.rcv <- ipkt
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-generation
func (h *line_handler) snd_open_pkt(cmd line_handler_snd_open, initiator bool) {
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

	if cmd.hashname == "" {
		cmd.reply <- errors.New("invalid line open request: must know hashname")
		return
	}

	if cmd.addr == nil {
		cmd.reply <- errors.New("invalid line open request: must know address")
		return
	}

	if cmd.pubkey == nil {
		cmd.reply <- errors.New("invalid line open request: must know public key")
		return
	}

	// check if line already exists
	line = h.snd_lines[cmd.hashname]
	if line != nil {
		if line.opened {
			// line is already opened
			cmd.reply <- nil
			return
		} else {
			if initiator {
				// wait for line to activate
				line.waiters = append(line.waiters, cmd.reply)
				return
			}
		}
	}

	if line == nil {
		line = &line_t{
			hashname: cmd.hashname,
			pubkey:   cmd.pubkey,
			addr:     cmd.addr,
		}
	}

	if initiator {
		line.waiters = append(line.waiters, cmd.reply)
	}

	{ // STEP 2:
		// - Generate an IV and a line identifier from a secure random source, both
		//   16 bytes
		iv, err = make_rand(16)
		if err != nil {
			cmd.reply <- err
			return
		}
		line_id, err = make_rand(16)
		if err != nil {
			cmd.reply <- err
			return
		}
		line.snd_id = hex.EncodeToString(line_id)
	}

	{ // STEP 3:
		// - Generate a new elliptic curve keypair, based on the "nistp256" curve
		ecc_prvkey, err = ecdh.GenerateKey(rand.Reader, elliptic.P256())
		if err != nil {
			cmd.reply <- err
			return
		}
		line.ecc_prvkey = ecc_prvkey
	}

	{ // STEP 4:
		// - SHA-256 hash the public elliptic key to form the encryption key for the
		//   inner packet
		ecc_pubkey, err = ecc_prvkey.PublicKey.Marshal()
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	{ // STEP 5:
		// - Form the inner packet containing a current timestamp at, line identifier,
		//   recipient hashname, and family (if you have such a value). Your own RSA
		rsapub_der, err = enc_DER_RSA(&h.key.PublicKey)
		if err != nil {
			cmd.reply <- err
			return
		}

		line.snd_at = time.Now()

		pkt := pkt_t{
			hdr: pkt_hdr_t{
				To:   line.hashname,
				At:   line.snd_at.Unix(),
				Line: line.snd_id,
			},
			body: rsapub_der,
		}

		inner_pkt, err = pkt.format_pkt()
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	{ // STEP 6:
		// - Encrypt the inner packet using the hashed public elliptic key from #4 and
		//   the IV you generated at #2 using AES-256-CTR.
		inner_pkt, err = enc_AES_256_CTR(hash_SHA256(ecc_pubkey), iv, inner_pkt)
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	{ // STEP 7:
		// - Create a signature from the encrypted inner packet using your own RSA
		//   keypair, a SHA 256 digest, and PKCSv1.5 padding
		inner_sig, err = rsa.SignPKCS1v15(rand.Reader, h.key, crypto.SHA256, hash_SHA256(inner_pkt))
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	{ // STEP 7.i:
		// - Encrypt the signature using a new AES-256-CTR cipher with the same IV and
		//   a new SHA-256 key hashed from the public elliptic key + the line value
		//   (16 bytes from #5), then base64 encode the result as the value for the
		//   sig param.
		outer_sig, err = enc_AES_256_CTR(hash_SHA256(ecc_pubkey, line_id), iv, inner_sig)
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	{ // STEP 8:
		// - Create an open param, by encrypting the public elliptic curve key you
		//   generated (in uncompressed form, aka ANSI X9.63) with the recipient's
		//   RSA public key and OAEP padding.
		open, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, line.pubkey, ecc_pubkey, nil)
		if err != nil {
			cmd.reply <- err
			return
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

		err = h.conn.send(&opkt)
		if err != nil {
			cmd.reply <- err
			return
		}
	}

	h.add_line(line)

	if !initiator {
		// done
		cmd.reply <- nil
	}
}

// See https://github.com/telehash/telehash.org/blob/feb3421b36a03e97f395f014a494f5dc90695f04/protocol.md#packet-processing-1
func (h *line_handler) rcv_open_pkt(opkt *pkt_t) {
	var (
		ipkt            *pkt_t
		err             error
		data            []byte
		iv              []byte
		line_id         []byte
		line            *line_t
		sig             []byte
		hashname        string
		ecc_pubkey_data []byte
		ecc_pubkey      *ecdh.PublicKey
		rsa_pubkey      *rsa.PublicKey
		aes_key_1       []byte
		aes_key_2       []byte
		at              time.Time
		now             = time.Now()
	)

	if opkt.hdr.Type != "open" {
		Log.Debug("open: type is not `open`")
		return // drop
	}

	// decode IV
	iv, err = hex.DecodeString(opkt.hdr.Iv)
	if err != nil {
		Log.Debug(err)
		return // drop
	}
	if len(iv) != 16 {
		Log.Debug("open: invalid iv")
		return // drop
	}

	// decode Sig
	sig, err = base64.StdEncoding.DecodeString(opkt.hdr.Sig)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	// STEP 1:
	// - Using your private key and OAEP padding, decrypt the open param,
	//   extracting the ECC public key (in uncompressed form) of the sender
	ecc_pubkey_data, err = base64.StdEncoding.DecodeString(opkt.hdr.Open)
	if err != nil {
		Log.Debug(err)
		return // drop
	}
	ecc_pubkey_data, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, h.key, ecc_pubkey_data, nil)
	if err != nil {
		Log.Debug(err)
		return // drop
	}
	ecc_pubkey, err = ecdh.UnmarshalPublic(ecc_pubkey_data)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	// STEP 2:
	// - Hash the ECC public key with SHA-256 to generate an AES key
	aes_key_1 = hash_SHA256(ecc_pubkey_data)

	// STEP 3:
	// - Decrypt the inner packet using the generated key and IV value with the
	//   AES-256-CTR algorithm.
	data, err = dec_AES_256_CTR(aes_key_1, iv, opkt.body)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	// parse inner pkt
	ipkt, err = parse_pkt(data, opkt.addr)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	// decode Line
	line_id, err = hex.DecodeString(ipkt.hdr.Line)
	if err != nil {
		Log.Debug(err)
		return // drop
	}
	if len(line_id) != 16 {
		err = errors.New("open: invalid line_id")
		Log.Debug(err)
		return // drop
	}

	// STEP 4:
	// - Verify the to value of the inner packet matches your hashname
	if ipkt.hdr.To != h.peers.get_local_hashname() {
		err = errors.New("open: hashname mismatch")
		Log.Debug(err)
		return // drop
	}

	// STEP 5:
	// - Extract the RSA public key of the sender from the inner packet BODY
	//   (binary DER format)
	rsa_pubkey, err = dec_DER_RSA(ipkt.body)
	if err != nil {
		Log.Debug(err)
		return // drop
	}

	// STEP 6:
	// - SHA-256 hash the RSA public key to derive the sender's hashname
	hashname = hex.EncodeToString(hash_SHA256(ipkt.body))

	// STEP 7:
	// - Verify the at timestamp is both within a reasonable amount of time to
	//   account for network delays and clock skew, and is newer than any other
	//   'open' requests received from the sender.
	at = time.Unix(ipkt.hdr.At, 0)
	if at.Before(now.Add(-h.max_time_skew)) || at.After(now.Add(h.max_time_skew)) {
		err = errors.New("open: open.at is too far of")
		Log.Debug(err)
		return // drop
	}

	line = h.snd_lines[hashname]
	if line != nil && line.rcv_at.After(at) {
		err = errors.New("open: open.rcv_at is older than another line")
		Log.Debug(err)
		return // drop
	}

	if line == nil {
		line = &line_t{
			hashname: hashname,
			pubkey:   rsa_pubkey,
			addr:     opkt.addr,
		}
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
		Log.Debug(err)
		h.drop_line(line, err)
		return // drop
	}

	// STEP 10:
	// - Using the RSA public key of the sender, verify the signature (decrypted
	//   in #9) of the original (encrypted) form of the inner packet
	err = rsa.VerifyPKCS1v15(rsa_pubkey, crypto.SHA256, hash_SHA256(opkt.body), sig)
	if err != nil {
		Log.Debug(err)
		h.drop_line(line, err)
		return // drop
	}

	// ====> Open packet is now verified <========================================

	line.rcv_id = hex.EncodeToString(line_id)
	line.ecc_pubkey = ecc_pubkey
	h.add_line(line)

	// STEP 11:
	// - If an open packet has not already been sent to this hashname, do so by
	//   creating one following the steps above
	if line.ecc_prvkey == nil {
		reply := make(chan error, 1)
		h.snd_open_pkt(line_handler_snd_open{
			hashname: line.hashname,
			pubkey:   line.pubkey,
			addr:     line.addr,
			reply:    reply,
		}, false)

		err = <-reply
		if err != nil {
			Log.Debug(err)
			h.drop_line(line, err)
			return // drop
		}
	}

	// STEP 12:
	// - After sending your own open packet in response, you may now generate a
	//   line shared secret using the received and sent ECC public keys and
	//   Elliptic Curve Diffie-Hellman (ECDH).
	if line.ecc_prvkey != nil {
		shared_key, err := line.ecc_prvkey.GenerateShared(line.ecc_pubkey, ecdh.MaxSharedKeyLength(line.ecc_pubkey))
		if err != nil {
			Log.Debug(err)
			h.drop_line(line, err)
			return // drop
		}

		snd_id, err := hex.DecodeString(line.snd_id)
		if err != nil {
			Log.Debug(err)
			h.drop_line(line, err)
			return // drop
		}

		rcv_id, err := hex.DecodeString(line.rcv_id)
		if err != nil {
			Log.Debug(err)
			h.drop_line(line, err)
			return // drop
		}

		line.enc_key = hash_SHA256(shared_key, snd_id, rcv_id)
		line.dec_key = hash_SHA256(shared_key, rcv_id, snd_id)
	}

	h.peers.add_peer(line.hashname, line.addr.String(), line.pubkey)

	// activate line and notify waiters
	line.opened = true
	line.pubkey = nil
	line.ecc_prvkey = nil
	line.ecc_pubkey = nil
	for _, waiter := range line.waiters {
		waiter <- nil
	}
	line.waiters = nil
	Log.Debugf("line opened: %s:%s (%s -> %s)",
		line.rcv_id,
		line.snd_id,
		h.peers.get_local_hashname()[:8],
		line.hashname[:8])

	return
}

func (h *line_handler) drop_line(line *line_t, err error) {
	h.lines_mtx.Lock()
	defer h.lines_mtx.Unlock()

	delete(h.snd_lines, line.hashname)
	delete(h.rcv_lines, line.rcv_id)
	for _, waiter := range line.waiters {
		waiter <- err
	}
}

func (h *line_handler) add_line(line *line_t) {
	h.lines_mtx.Lock()
	defer h.lines_mtx.Unlock()

	h.snd_lines[line.hashname] = line
	h.rcv_lines[line.rcv_id] = line
}

func (h *line_handler) get_rcv_line(id string) *line_t {
	h.lines_mtx.RLock()
	defer h.lines_mtx.RUnlock()

	return h.rcv_lines[id]
}

func (h *line_handler) get_snd_line(id string) *line_t {
	h.lines_mtx.RLock()
	defer h.lines_mtx.RUnlock()

	return h.snd_lines[id]
}

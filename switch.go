package telehash

import "fmt"
import "net"
import "crypto/rsa"
import "encoding/base64"
import "encoding/hex"

const (
	CMD_OPENLINE uint8 = iota
	CMD_DELIVER
)

type switchCommand struct {
	id uint8
	packet *Packet
}


type Switch struct {
	lines map[string]*Line	// LineId -> Line
	peers map[string]*Line	// Hashname -> Line

	identity *rsa.PrivateKey

	keys map[string]*rsa.PublicKey // Hashname -> public key

	commandQueue chan(switchCommand)

	conn *net.UDPConn

	lastReadError error
}

func NewSwitch(addr string, key *rsa.PrivateKey) (s *Switch, err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	s = &Switch { conn: udpConn,
		identity: key,
		commandQueue: make(chan switchCommand),
	}

	// Spin up a goroutine to listen for inbound packets
	go s.readPacketLoop()

	// Spin up a goroutine for handling state changes within Switch
	go s.commandLoop()

	return
}

func (s *Switch) readPacketLoop() {
	for {
		buf := make([]byte, 1500)
		count, sourceAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Read failed; note the error and shutdown
			s.lastReadError = err
			return
		}

		p, err := NewPacket(buf[:count], sourceAddr)
		if err != nil {
			// Decoding packet failed; ignore it
			continue
		}

		// Pass the packet off to the command queue for delivery;
		// drops unknown packet types
		switch p.Headers.Type {
		case "open":
			s.commandQueue <- switchCommand{ CMD_OPENLINE, p }
		case "line":
			s.commandQueue <- switchCommand{ CMD_DELIVER, p }
		}
	}
}

func (s *Switch) commandLoop() {
	for {
		cmd := <-s.commandQueue
		switch cmd.id {
		case CMD_OPENLINE:
			s.openLine(cmd.packet)
		case CMD_DELIVER:
			line := s.lines[cmd.packet.Headers.Line]
			if line != nil {
				line.receive(cmd.packet)
			}
		}
	}
}

func (s *Switch) openLine(p *Packet) {
	// Extract and decode relevant portions of the packet
	sigBin, _  := base64.StdEncoding.DecodeString(p.Headers.Sig)
	openBin, _ := base64.StdEncoding.DecodeString(p.Headers.Open)
	ivBin, _   := hex.DecodeString(p.Headers.Iv)
	if sigBin == nil || openBin == nil || ivBin == nil {
		// Drop the packet
		return
	}

	// Decrypt the "open" header and extract the source's ephemeral EC key
	ecKeyRaw, err := DecryptWithRSA(s.identity, openBin)
	if err != nil {
		// Decryption failed; drop the packet
		return
	}

	// The raw EC key is used as key material to decrypt the body of
	// the request. Note that we have to decrypt before validating signature
	// since the sender's identity is in the encrypted portion of packet.
	innerBin, err := decryptWithAES(sha256Hash(ecKeyRaw), ivBin, p.Body)
	if err != nil {
		// Decryption of body failed; drop the packet
		return
	}

	// Convert the decrypted body into a proper packet
	innerPacket, err := NewPacket(innerBin, nil)
	if err != nil {
		// Packet was not well-formed; drop the packet
		return
	}

	// Extract the sender's public key from the body of the inner packet and
	// use it to calculate their hashname
	senderPubKey, err := derToPubKey(innerPacket.Body)
	if err != nil {
		// Couldn't decode the public key
		return
	}
	//senderHashname := sha256Hash(innerPacket.Body)

	// TODO: Track pub keys persistently so we can detect changes

	// Validate the signature
	if !IsSignatureValid(senderPubKey, p.Body, sigBin) {
		// Signature isn't valid; warn but keep going for moment
		fmt.Printf("Failed to validate signature!")
	}

	// Now, look 

	// Decode the packet
	var line *Line
	hashname := ""
	lineId := ""

	line, found := s.peers[hashname]
	if found {
		// Line already exists; we need to remove entry for old
		// line to ensure proper routing for future packets
		delete(s.lines, line.sourceId)
	} else {
		// Line doesn't exist yet; create a new one
		line, _ = newLine(s)
	}

	// Update lookup tables for the line
	s.lines[lineId] = line
	s.peers[hashname] = line

	// Activate the line
	line.activate(p)
}

// func (s *Switch) AddIdentity(tag string, key rsa.PrivateKey) {}

func (s *Switch) OpenLine(key rsa.PublicKey, addr *net.UDPAddr) (line *Line, err error) {
	return
}

// func (l *Line) Query(request Packet) (response Packet, err error) {}




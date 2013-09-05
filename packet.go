package telehash

import "bytes"
import "encoding/json"
import "encoding/binary"
import "net"

type PacketHeaders struct {
	Type   string `json:",omitempty"`
	Line   string `json:",omitempty"`
	Iv     string `json:",omitempty"`
	Stream string `json:",omitempty"`
	Open   string `json:",omitempty"`
	To     string `json:",omitempty"`
	Sig    string `json:",omitempty"`
}

type Packet struct {
	Headers     PacketHeaders
	Body        []byte
	Source      net.UDPAddr
}

func (p *Packet) Marshal() (b []byte, err error) {
	headerBytes, err := json.Marshal(p.Headers)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, len(headerBytes))
	buf.Write(headerBytes)

	if p.Body != nil {
		buf.Write(p.Body)
	}

	return buf.Bytes(), nil
}

func NewPacket(b []byte, sourceAddr *net.UDPAddr) (p *Packet, err error) {
	// Extract size of the JSON headers
	var jsonSz uint16
	err = binary.Read(bytes.NewBuffer(b), binary.BigEndian, &jsonSz)
	if err != nil {
		return nil, err
	}

	// Unpack the headers
	headers := PacketHeaders{}
	err = json.Unmarshal(b[3:3 + jsonSz], headers)
	if err != nil {
		return nil, err
	}

	return &Packet {
		Headers: headers,
		Body: b[3+jsonSz:len(b)],
		Source: *sourceAddr,
	}, nil
}



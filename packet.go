package telehash

import "encoding/json"
import "encoding/binary"

type Packet struct {
	Headers map[string]interface{}
	Body    byte[]
}

func (p *Packet) Type() string {
	return p.Headers["type"]
}

func NewPacket(b []byte) (*Packet, error) {
	// Extract size of the JSON headers
	var jsonSz uint16
	err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &jsonSz)
	if err != nil {
		return nil, err
	}

	// Unpack the headers
	headers := make(map[string]interface{})
	err := json.Unmarshal(b[3:3 + jsonSz], headers)
	if err != nil {
		return nil, err
	}

	return &Packet { Headers: headers, Body: b[3+jsonSz:len(b)] }, nil
}

func (p *Packet) Encode() (byte[], err) {
	headerBytes, err := json.Marshal(p.Headers)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, headerBytes.len())
	buf.Write(headerBytes)

	if p.Body != nil {
		buf.Write(p.Body)
	}

	return buf.Bytes(), nil
}

func (p *Packet) Decode(buf byte[]) 

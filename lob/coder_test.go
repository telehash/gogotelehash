package lob

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestCreatePacket(t *testing.T) {
	head := []byte{1, 2, 3}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head, body}

	if len(head) != len(p.Head) {
		t.Errorf("Header lenght incorrect, %d != %d", len(head), len(p.Head))
	}

	if len(body) != len(p.Body) {
		t.Errorf("Body lenght incorrect, %d != %d", len(body), len(p.Body))
	}
}

func TestEncodeBinaryPacket(t *testing.T) {
	head := []byte{1, 2, 3}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head, body}

	b, _ := p.MarshalBinary()

	if len(b) != 2+len(head)+len(body) {
		t.Errorf("Encoded lenght incorrect, %d != %d", len(b), 2+len(head)+len(body))
	}

	encLen := int(binary.BigEndian.Uint16(b[0:2]))
	if encLen != len(head) {
		t.Errorf("Header lenght incorrect, %d != %d", len(head), encLen)
	}

	encHead := b[2 : 2+encLen]
	if !bytes.Equal(encHead, head) {
		t.Error("Header encoding incorrect")
	}

	encBody := b[5:]
	if !bytes.Equal(encBody, body) {
		t.Error("Body encoding incorrect")
	}
}

func TestDecodeBinaryPacket(t *testing.T) {
	raw := []byte{0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	p := &Packet{}

	_ = p.UnmarshalBinary(raw)

	encLen := int(binary.BigEndian.Uint16(raw[0:2]))
	if encLen != len(p.Head) {
		t.Errorf("Header lenght incorrect, %d != %d", len(p.Head), encLen)
	}

	encHead := raw[2 : 2+encLen]
	if !bytes.Equal(encHead, p.Head) {
		t.Error("Header encoding incorrect")
	}

	encBody := raw[2+encLen:]
	if !bytes.Equal(encBody, p.Body) {
		t.Error("Body encoding incorrect")
	}
}

func TestEncodeMaxLengthHeader(t *testing.T) {
	head := [math.MaxUint16]byte{}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head[:], body}

	b, err := p.MarshalBinary()
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(b) != 2+len(head[:])+len(body) {
		t.Errorf("Encoded lenght incorrect, %d != %d", len(b), 2+len(head)+len(body))
	}

	encLen := int(binary.BigEndian.Uint16(b[0:2]))
	if encLen != len(head) {
		t.Errorf("Header lenght incorrect, %d != %d", len(head), encLen)
	}

	encHead := b[2 : 2+encLen]
	if !bytes.Equal(encHead, head[:]) {
		t.Error("Header encoding incorrect")
	}

	encBody := b[2+encLen:]
	if !bytes.Equal(encBody, body) {
		t.Errorf("Body encoding incorrect, %v != %v", encBody, body)
	}
}

func TestEncodeTooLongHeader(t *testing.T) {
	head := [math.MaxUint16 + 1]byte{}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head[:], body}

	_, err := p.MarshalBinary()
	if err != ErrHeaderTooLong {
		t.Errorf("Encoded header that is longer than %v bytes, %v", math.MaxUint16, err)
	}
}

func TestEncodeDecodeEmptyHeader(t *testing.T) {
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{}
	p.Body = body
	b, _ := p.MarshalBinary()

	p2 := &Packet{}
	_ = p2.UnmarshalBinary(b)

	if !bytes.Equal(p.Head, p2.Head) {
		t.Errorf("Re decoded header not equal, %v != %v", p.Head, p2.Head)
	}

	if len(p.Head) != 0 {
		t.Errorf("Original Header not emtpy, len=%v", len(p.Head))
	}

	if len(p2.Head) != 0 {
		t.Errorf("Decoded Header not emtpy, len=%v", len(p2.Head))
	}

	if !bytes.Equal(p.Body, p2.Body) {
		t.Errorf("Re decoded body not equal, %v != %v", p.Body, p2.Body)
	}
}

func TestEncodeDecodeBinaryHeader(t *testing.T) {
	head := []byte{1, 2, 3}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head, body}
	b, _ := p.MarshalBinary()

	p2 := &Packet{}
	_ = p2.UnmarshalBinary(b)

	if !bytes.Equal(p.Head, p2.Head) {
		t.Errorf("Re decoded header not equal, %v != %v", p.Head, p2.Head)
	}

	if !bytes.Equal(p.Body, p2.Body) {
		t.Errorf("Re decoded body not equal, %v != %v", p.Body, p2.Body)
	}
}

func TestEncodeDecodeJSONHeader(t *testing.T) {
	type testHead struct {
		FirstField  int
		SecondField string
	}
	head := testHead{1, "my field"}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{}
	p.Body = body
	p.Head.EncodeJSON(head)
	b, _ := p.MarshalBinary()

	p2 := &Packet{}
	_ = p2.UnmarshalBinary(b)

	var head2 testHead
	p2.Head.DecodeJSON(&head2)

	if head != head2 {
		t.Errorf("Re decoded JSON header not equal, %v != %v", head, head2)
	}

	if !bytes.Equal(p.Head, p2.Head) {
		t.Errorf("Re decoded header not equal, %v != %v", p.Head, p2.Head)
	}

	if !bytes.Equal(p.Body, p2.Body) {
		t.Errorf("Re decoded body not equal, %v != %v", p.Body, p2.Body)
	}

}

func TestEncodeDecodeBinaryHeaderAsJSON(t *testing.T) {
	type testHead struct {
		FirstField  int
		SecondField string
	}

	head := []byte{1, 2, 3}
	body := []byte{4, 5, 6, 7, 8, 9}

	p := &Packet{head, body}
	b, _ := p.MarshalBinary()

	p2 := &Packet{}
	_ = p2.UnmarshalBinary(b)

	var head2 testHead
	err := p2.Head.DecodeJSON(&head2)
	if err != ErrNonJSONHeader {
		t.Errorf("Non JSON header was decoded as JSON, %v", err)
	}

	if !bytes.Equal(p.Head, p2.Head) {
		t.Errorf("Re decoded header not equal, %v != %v", p.Head, p2.Head)
	}

	if !bytes.Equal(p.Body, p2.Body) {
		t.Errorf("Re decoded body not equal, %v != %v", p.Body, p2.Body)
	}
}

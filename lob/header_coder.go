package lob

import (
	"bytes"
	"encoding/json"
)

type tHeader struct {
	C       uint32
	Type    string
	Seq     uint32
	Ack     uint32
	Miss    []uint32
	HasC    bool
	HasType bool
	HasSeq  bool
	HasAck  bool
	HasMiss bool

	Extra map[string]interface{}
}

var (
	objectBeg  = []byte("{")
	objectEnd  = []byte("}")
	arrayBeg   = []byte("[")
	arrayEnd   = []byte("]")
	tokenColon = []byte(":")
	tokenComma = []byte(",")

	hdrC    = []byte(`"c"`)
	hdrType = []byte(`"type"`)
	hdrSeq  = []byte(`"seq"`)
	hdrAck  = []byte(`"ack"`)
	hdrMiss = []byte(`"miss"`)
)

func parseHeader(hdr *tHeader, p []byte) error {
	var (
		ok  bool
		err error
	)

	if p, ok = parsePrefix(p, objectBeg); !ok {
		return ErrInvalidPacket
	}

	for {
		var (
			f   func(hdr *tHeader, key string, p []byte) ([]byte, error)
			key string
		)

		if p, ok = parsePrefix(p, hdrC); ok {
			f = parseC
		} else if p, ok = parsePrefix(p, hdrSeq); ok {
			f = parseSeq
		} else if p, ok = parsePrefix(p, hdrAck); ok {
			f = parseAck
		} else if p, ok = parsePrefix(p, hdrMiss); ok {
			f = parseMiss
		} else if p, ok = parsePrefix(p, hdrType); ok {
			f = parseType
		} else if key, p, ok = parseString(p); ok {
			f = parseOther
		}

		if p, ok = parsePrefix(p, tokenColon); !ok {
			return ErrInvalidPacket
		}

		if p, err = f(hdr, key, p); err != nil {
			return err
		}

		if p, ok = parsePrefix(p, tokenComma); ok {
			continue
		} else if p, ok = parsePrefix(p, objectEnd); ok {
			return nil
		} else {
			return ErrInvalidPacket
		}
	}
}

func parseC(hdr *tHeader, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.C = n
	hdr.HasC = true
	return p, nil
}

func parseMiss(hdr *tHeader, key string, p []byte) ([]byte, error) {
	var (
		l  []uint32
		n  uint32
		ok bool
	)

	if p, ok = parsePrefix(p, arrayBeg); !ok {
		return nil, ErrInvalidPacket
	}

	for {
		if len(p) == 0 {
			return nil, ErrInvalidPacket
		}

		if n, p, ok = parseUint32(p); !ok {
			return nil, ErrInvalidPacket
		}
		l = append(l, n)

		if p, ok = parsePrefix(p, tokenComma); ok {
			continue
		} else if p, ok = parsePrefix(p, arrayEnd); ok {
			break
		} else {
			return nil, ErrInvalidPacket
		}
	}

	hdr.Miss = l
	hdr.HasMiss = true
	return p, nil
}

func parseSeq(hdr *tHeader, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Seq = n
	hdr.HasSeq = true
	return p, nil
}

func parseAck(hdr *tHeader, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Ack = n
	hdr.HasAck = true
	return p, nil
}

func parseType(hdr *tHeader, key string, p []byte) ([]byte, error) {
	s, p, ok := parseString(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Type = s
	hdr.HasType = true
	return p, nil
}

func parseOther(hdr *tHeader, key string, p []byte) ([]byte, error) {
	v, p, ok := scanAny(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	var x interface{}
	err := json.Unmarshal(v, &x)
	if err != nil {
		return nil, ErrInvalidPacket
	}

	if hdr.Extra == nil {
		hdr.Extra = make(map[string]interface{})
	}
	hdr.Extra[key] = x
	return p, nil
}

func parseUint32(p []byte) (uint32, []byte, bool) {
	p = skipSpace(p)
	var n uint32

	if len(p) == 0 {
		return 0, p, false
	}

	for idx, r := range p {
		if '0' <= r && r <= '9' {
			n = (n * 10) + (uint32(r) - '0')
			continue
		}

		if idx == 0 {
			return 0, p, false
		}

		p = p[idx:]
	}

	return n, p, true
}

func parseString(p []byte) (string, []byte, bool) {
	v, p, ok := scanString(p)
	if !ok {
		return "", p, false
	}

	var s string
	err := json.Unmarshal(v, &s)
	if err != nil {
		return "", p, false
	}

	return s, p, true
}

func scanString(p []byte) ([]byte, []byte, bool) {
	p = skipSpace(p)

	if len(p) == 0 {
		return nil, p, false
	}

	var escape bool

	for idx, r := range p {

		if idx == 0 {
			if r != '"' {
				return nil, p, false
			}
			continue
		}

		if escape {
			escape = false
			continue
		}

		if r == '\\' {
			escape = true
			continue
		}

		if r == '"' {
			return p[:idx+1], p[idx+1:], true
		}

	}

	return nil, p, false
}

func parsePrefix(p, prefix []byte) ([]byte, bool) {
	p = skipSpace(p)
	if bytes.HasPrefix(p, prefix) {
		return p[len(prefix):], true
	}
	return p, false
}

func skipSpace(p []byte) []byte {
	for idx, r := range p {
		if !(r == ' ' || r == '\t' || r == '\n') {
			return p[idx:]
		}
	}
	return nil
}

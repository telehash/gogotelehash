package lob

import (
	"bytes"
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

var (
	objectBeg  = []byte("{")
	objectEnd  = []byte("}")
	arrayBeg   = []byte("[")
	arrayEnd   = []byte("]")
	tokenColon = []byte(":")
	tokenComma = []byte(",")
	tokenTrue  = []byte("true")
	tokenFalse = []byte("false")

	hdrC    = []byte(`"c"`)
	hdrType = []byte(`"type"`)
	hdrSeq  = []byte(`"seq"`)
	hdrAck  = []byte(`"ack"`)
	hdrMiss = []byte(`"miss"`)
	hdrEnd  = []byte(`"end"`)
)

func parseHeader(hdr *Header, p []byte) error {
	var (
		ok  bool
		err error
	)

	if p, ok = parsePrefix(p, objectBeg); !ok {
		return ErrInvalidPacket
	}

	for {
		var (
			f   func(hdr *Header, key string, p []byte) ([]byte, error)
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
		} else if p, ok = parsePrefix(p, hdrEnd); ok {
			f = parseEnd
		} else if key, p, ok = parseString(p); ok {
			f = parseOther
		} else {
			return ErrInvalidPacket
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

func parseC(hdr *Header, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.C = n
	hdr.HasC = true
	return p, nil
}

func parseMiss(hdr *Header, key string, p []byte) ([]byte, error) {
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

func parseSeq(hdr *Header, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Seq = n
	hdr.HasSeq = true
	return p, nil
}

func parseAck(hdr *Header, key string, p []byte) ([]byte, error) {
	n, p, ok := parseUint32(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Ack = n
	hdr.HasAck = true
	return p, nil
}

func parseType(hdr *Header, key string, p []byte) ([]byte, error) {
	s, p, ok := parseString(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.Type = s
	hdr.HasType = true
	return p, nil
}

func parseEnd(hdr *Header, key string, p []byte) ([]byte, error) {
	b, p, ok := parseBool(p)
	if !ok {
		return nil, ErrInvalidPacket
	}

	hdr.End = b
	hdr.HasEnd = true
	return p, nil
}

func parseOther(hdr *Header, key string, p []byte) ([]byte, error) {
	v, p, ok := scanAnyObjectValue(p)
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

func parseBool(p []byte) (bool, []byte, bool) {
	p = skipSpace(p)

	var (
		ok bool
		b  bool
	)

	if p, ok = parsePrefix(p, tokenTrue); ok {
		b = true
	} else if p, ok = parsePrefix(p, tokenFalse); ok {
		b = false
	} else {
		return false, p, false
	}

	return b, p, true
}

func parseUint32(p []byte) (uint32, []byte, bool) {
	o := p
	p = skipSpace(p)
	var (
		n uint32
	)

	if len(p) == 0 {
		return 0, p, false
	}

	for idx, r := range p {
		if '0' <= r && r <= '9' {
			n = n*10 + (uint32(r) - '0')
			continue
		}

		if idx == 0 {
			return 0, p, false
		}

		p = p[idx:]
		break
	}

	p = skipSpace(p)
	if len(p) == 0 || p[0] == ']' || p[0] == '}' || p[0] == ',' {
		return n, p, true
	}

	return 0, o, false
}

func parseString(p []byte) (string, []byte, bool) {
	v, p, ok := scanString(p)
	if !ok {
		return "", p, false
	}

	var (
		numericBuf [4]byte
	)

	var dst int
	var sze = len(v) - 1
	for src := 1; src < sze; src++ {
		r := v[src]

		switch r {
		case '\\':
			src++
			if src >= sze {
				return "", p, false
			}
			r = v[src]

			switch r {

			case '"':
				v[dst] = '"'
				dst++
			case '\\':
				v[dst] = '\\'
				dst++
			case '/':
				v[dst] = '/'
				dst++
			case 'b':
				v[dst] = '\b'
				dst++
			case 'f':
				v[dst] = '\f'
				dst++
			case 'n':
				v[dst] = '\n'
				dst++
			case 'r':
				v[dst] = '\r'
				dst++
			case 't':
				v[dst] = '\t'
				dst++

			case 'u':
				numeric := numericBuf[:]
				numericCount := 0
			unicode_loop:
				for {
					src++
					if src >= sze {
						return "", p, false
					}
					r = v[src]

					switch {
					case r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F':
						numeric[numericCount] = byte(r)
						numericCount++
						if numericCount == 4 {
							var i int64
							var err error
							if i, err = strconv.ParseInt(string(numeric), 16, 32); err != nil {
								return "", p, false
							}
							if i < utf8.RuneSelf {
								v[dst] = byte(i)
								dst++
							} else {
								encoded := utf8.EncodeRune(v[dst:], rune(i))
								dst += encoded
							}
							break unicode_loop
						}
					default:
						return "", p, false

					}
				}
			default:
				return "", p, false

			}

		default:
			v[dst] = r
			dst++

		}
	}

	return string(v[:dst]), p, true
}

func scanString(p []byte) ([]byte, []byte, bool) {
	beg, end, ok := scanStringIdx(p)
	if !ok {
		return nil, p, false
	}

	return p[beg:end], p[end:], true
}

func scanStringIdx(p []byte) (beg, end int, ok bool) {
	beg = scanSpace(p)
	p = p[beg:]

	if len(p) == 0 {
		return 0, 0, false
	}

	var escape bool

	for idx, r := range p {

		if idx == 0 {
			if r != '"' {
				return 0, 0, false
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
			end = beg + idx + 1
			return beg, end, true
		}

	}

	return 0, 0, false
}

func parsePrefix(p, prefix []byte) ([]byte, bool) {
	p = skipSpace(p)
	if bytes.HasPrefix(p, prefix) {
		return p[len(prefix):], true
	}
	return p, false
}

func skipSpace(p []byte) []byte {
	return p[scanSpace(p):]
}

func scanSpace(p []byte) int {
	for idx, r := range p {
		if !(r == ' ' || r == '\t' || r == '\n') {
			return idx
		}
	}
	return 0
}

func scanAnyObjectValue(p []byte) (json.RawMessage, []byte, bool) {
	var (
		buf = p
		idx = 0
	)

	for len(p) > 0 {
		switch p[0] {

		case '"':
			_, end, ok := scanStringIdx(p)
			if !ok {
				return nil, buf, false
			}
			idx += end
			p = p[end:]

		case '{':
			end, ok := scanObject(p[1:])
			if !ok {
				return nil, buf, false
			}
			idx += end
			p = p[end:]

		case '[':
			end, ok := scanArray(p[1:])
			if !ok {
				return nil, buf, false
			}
			idx += end
			p = p[end:]

		case ',', '}':
			return json.RawMessage(buf[:idx]), p, true

		default:
			idx += 1
			p = p[1:]

		}
	}

	return nil, nil, false
}

func scanObject(p []byte) (int, bool) {
	var (
		idx = 1
	)

	for len(p) > 0 {
		switch p[0] {

		case '"':
			_, end, ok := scanStringIdx(p)
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case '{':
			end, ok := scanObject(p[1:])
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case '[':
			end, ok := scanArray(p[1:])
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case '}':
			return idx + 1, true

		default:
			idx += 1
			p = p[1:]

		}
	}

	return 0, false
}

func scanArray(p []byte) (int, bool) {
	var (
		idx = 1
	)

	for len(p) > 0 {
		switch p[0] {

		case '"':
			_, end, ok := scanStringIdx(p)
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case '{':
			end, ok := scanObject(p[1:])
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case '[':
			end, ok := scanArray(p[1:])
			if !ok {
				return 0, false
			}
			idx += end
			p = p[end:]

		case ']':
			return idx + 1, true

		default:
			idx += 1
			p = p[1:]

		}
	}

	return 0, false
}

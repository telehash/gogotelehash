// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package base32 implements base32 encoding as specified by RFC 4648.
package base32

import (
	"unicode"
)

// I => 1
// L => 1
// O => 0
// S => 5
const encodeMap = "0123456789abcdefghjkmnpqrtuvwxyz"

var decodeMap = func() [256]byte {
	var m [256]byte
	for i := 0; i < 256; i++ {
		m[i] = 0xFF
	}
	for i, c := range encodeMap {
		m[unicode.ToUpper(rune(c))] = byte(i)
		m[c] = byte(i)
		if c == '1' {
			m['i'] = byte(i)
			m['I'] = byte(i)
			m['l'] = byte(i)
			m['L'] = byte(i)
		}
		if c == '0' {
			m['o'] = byte(i)
			m['O'] = byte(i)
		}
		if c == '5' {
			m['s'] = byte(i)
			m['S'] = byte(i)
		}
	}
	return m
}()

func Encode(dst, src []byte) {
	var (
		buf  uint64
		bits uint

		j = 0
	)

	for _, c := range src {
		buf = buf<<8 | uint64(c)
		bits += 8

		for bits > 5 {
			dst[j] = encodeMap[buf>>(bits-5)&0x1F]
			j++
			bits -= 5
		}
	}

	if bits > 0 {
		buf = buf << (5 - bits)
		dst[j] = encodeMap[buf&0x1F]
	}
}

func EncodeToString(p []byte) string {
	buf := make([]byte, EncodedLen(len(p)))
	Encode(buf, p)
	return string(buf)
}

func Decode(dst, src []byte) (int, error) {
	var (
		buf  uint64
		bits uint

		j = 0
	)

	for _, c := range src {
		if c == '=' {
			break
		}

		buf = buf<<5 | uint64(decodeMap[c])
		bits += 5

		for bits >= 8 {
			dst[j] = byte(buf >> (bits - 8) & 0xFF)
			j++
			bits -= 8
		}
	}

	return j, nil
}

func DecodeString(s string) ([]byte, error) {
	var buf = make([]byte, DecodedLen(len(s)))
	_, err := Decode(buf, []byte(s))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func EncodedLen(n int) int {
	b := n * 8
	n = b / 5
	if b%5 > 0 {
		n++
	}
	return n
}

func DecodedLen(n int) int {
	return n * 5 / 8
}

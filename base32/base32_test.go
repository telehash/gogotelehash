// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base32

import (
	"testing"
)

type testpair struct {
	decoded, encoded string
}

var pairs = []testpair{
	// RFC 4648 examples
	{"", ""},
	{"f", "cr"},
	{"fo", "ctqg"},
	{"foo", "ctqpy"},
	{"foob", "ctqpyrg"},
	{"fooba", "ctqpyrk1"},
	{"foobar", "ctqpyrk1e8"},

	// Wikipedia examples, converted to base32
	{"sure.", "eduq4t9e"},
	{"sure", "eduq4t8"},
	{"sur", "eduq4"},
	{"su", "edug"},
	{"leasure.", "dhjp2wvne9jjw"},
	{"easure.", "cngq6xbjcmq0"},
	{"asure.", "c5tqawk55r"},
	{"sure.", "eduq4t9e"},

	// NPM: base32
	{"lowercase UPPERCASE 1234567 !@#$%^&*", "dhqqetbjcdgq6t90an850haj8d0n6h9064t36d1n6rvj08a04cj2aqh658"},
}

var bigtest = testpair{
	"Twas brillig, and the slithy toves",
	"ahvp2wt0c9t6jv3cd5kjr831dtj20x38cmg76v39ehm7j83mdxv6awr",
}

func testEqual(t *testing.T, msg string, args ...interface{}) bool {
	if args[len(args)-2] != args[len(args)-1] {
		t.Errorf(msg, args...)
		return false
	}
	return true
}

func TestEncode(t *testing.T) {
	for _, p := range pairs {
		got := EncodeToString([]byte(p.decoded))
		testEqual(t, "Encode(%q) = %q, want %q", p.decoded, got, p.encoded)
	}
}

func TestDecode(t *testing.T) {
	for _, p := range pairs {
		dbuf := make([]byte, DecodedLen(len(p.encoded)))
		count, err := Decode(dbuf, []byte(p.encoded))
		testEqual(t, "Decode(%q) = error %v, want %v", p.encoded, err, error(nil))
		testEqual(t, "Decode(%q) = length %v, want %v", p.encoded, count, len(p.decoded))
		testEqual(t, "Decode(%q) = %q, want %q", p.encoded,
			string(dbuf[0:count]),
			p.decoded)

		dbuf, err = DecodeString(p.encoded)
		testEqual(t, "DecodeString(%q) = error %v, want %v", p.encoded, err, error(nil))
		testEqual(t, "DecodeString(%q) = %q, want %q", p.encoded, string(dbuf), p.decoded)
	}
}

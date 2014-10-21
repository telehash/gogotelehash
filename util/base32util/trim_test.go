package base32util

import (
	"bytes"
	"strings"
	"testing"
	"testing/quick"
)

func TestAddRemovePadding(t *testing.T) {
	var tab = [][2]string{
		{"", ""},
		{"f", "my"},
		{"fo", "mzxq"},
		{"foo", "mzxw6"},
		{"foob", "mzxw6yq"},
		{"fooba", "mzxw6ytb"},
		{"foobar", "mzxw6ytboi"},
		{"foobarb", "mzxw6ytbojra"},
		{"foobarba", "mzxw6ytbojrgc"},
		{"foobarbax", "mzxw6ytbojrgc6a"},
	}
	for i, r := range tab {
		x := EncodeToString([]byte(r[0]))
		if x != r[1] {
			t.Errorf("#%d failed expected %q instead of %q for EncodeToString", i, r[1], x)
		}

		y, _ := DecodeString(x)
		if string(y) != r[0] {
			t.Errorf("#%d failed expected %q instead of %q for DecodeString", i, r[1], string(y))
		}
	}

	f := func(x0 []byte) bool {
		y0 := EncodeToString(x0)

		if strings.ContainsRune(y0, '=') {
			return false
		}

		x1, err := DecodeString(y0)
		if err != nil || !bytes.Equal(x0, x1) {
			return false
		}

		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

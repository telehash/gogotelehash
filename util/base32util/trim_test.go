package base32util

import (
	"bytes"
	"strings"
	"testing"
	"testing/quick"
)

func TestAddRemovePadding(t *testing.T) {
	var tab = [][3]string{
		{"", "", ""},
		{"f", "my======", "my"},
		{"fo", "mzxq====", "mzxq"},
		{"foo", "mzxw6===", "mzxw6"},
		{"foob", "mzxw6yq=", "mzxw6yq"},
		{"fooba", "mzxw6ytb", "mzxw6ytb"},
		{"foobar", "mzxw6ytboi======", "mzxw6ytboi"},
		{"foobarb", "mzxw6ytbojra====", "mzxw6ytbojra"},
		{"foobarba", "mzxw6ytbojrgc===", "mzxw6ytbojrgc"},
		{"foobarbax", "mzxw6ytbojrgc6a=", "mzxw6ytbojrgc6a"},
	}
	for i, r := range tab {
		x := Encoding.EncodeToString([]byte(r[0]))
		if x != r[1] {
			t.Errorf("#%d failed expected %q instead of %q for EncodeToString", i, r[1], x)
		}

		x = RemovePadding(x)
		if x != r[2] {
			t.Errorf("#%d failed expected %q instead of %q for RemovePadding", i, r[2], x)
		}

		x = AddPadding(x)
		if x != r[1] {
			t.Errorf("#%d failed expected %q instead of %q for AddPadding", i, r[1], x)
		}
	}

	f := func(x0 []byte) bool {
		y0 := Encoding.EncodeToString(x0)

		y1 := RemovePadding(y0)

		if strings.ContainsRune(y1, '=') {
			return false
		}

		y2 := AddPadding(y1)
		if y0 != y2 {
			return false
		}

		x1, err := Encoding.DecodeString(y2)
		if err != nil || !bytes.Equal(x0, x1) {
			return false
		}

		y3 := AddPadding(y0)
		if y0 != y3 {
			return false
		}

		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

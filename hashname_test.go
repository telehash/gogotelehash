package telehash

import (
	"fmt"
	"testing"
)

func TestHashnameFromString(t *testing.T) {
	var table = map[string]string{
		"":      "Er: telehash: invalid hashname",
		"hello": "Er: telehash: invalid hashname",
		"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c":        "Ok: 1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
		"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c1237913": "Er: telehash: invalid hashname",
		"1700b2d3081151021b4338":                                                  "Er: telehash: invalid hashname",
	}

	for i, e := range table {
		hn, err := HashnameFromString(i)
		a := ""
		if err == nil {
			a = fmt.Sprintf("Ok: %s", hn)
		} else {
			a = fmt.Sprintf("Er: %s", err)
		}
		if a != e {
			t.Errorf("hashname=%q expected=%q actual=%q", i, e, a)
		}
	}
}

func TestHashnamePrefix(t *testing.T) {
	var table = [][]string{
		{
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"181042800434dd49c45299c6c3fc69ab427ec49862739b6449e1fcd77b27d3a6",
			"18",
		},
		{
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"171042800434dd49c45299c6c3fc69ab427ec49862739b6449e1fcd77b27d3a6",
			"1710",
		},
		{
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
		},
		{
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff1807ee",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff1807ee",
		},
		{
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff18075c",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff1817ee",
			"1700b2d3081151021b4338294c9cec4bf84a2c8bdf651ebaa976df8cff1817",
		},
	}

	for _, row := range table {
		ha, hb, e := hn(row[0]), hn(row[1]), row[2]

		a := HashnamePrefix(ha, hb)
		if e != a {
			t.Errorf("a=%s b=%s expected=%q actual=%q", ha, hb, e, a)
		}
	}
}

func hn(s string) Hashname {
	h, err := HashnameFromString(s)
	if err != nil {
		panic(err)
	}
	return h
}

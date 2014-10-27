package tack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	var tab = []struct {
		String string
		Tack   *Tack
		Error  string
	}{

		{
			"app:alias@canonical/token",
			&Tack{"app", "alias", "canonical", "token"},
			"",
		},

		{
			"canonical",
			&Tack{"", "", "canonical", ""},
			"",
		},

		{
			"alias@canonical",
			&Tack{"", "alias", "canonical", ""},
			"",
		},

		{
			"canonical/token",
			&Tack{"", "", "canonical", "token"},
			"",
		},

		{
			"app:canonical",
			&Tack{"app", "", "canonical", ""},
			"",
		},

		{
			"app:alias@canonical",
			&Tack{"app", "alias", "canonical", ""},
			"",
		},

		{
			"app:canonical/token",
			&Tack{"app", "", "canonical", "token"},
			"",
		},

		{
			"app:alias@/token",
			nil,
			"invalid tack: missing canonical component",
		},

		{
			"app:alias@",
			nil,
			"invalid tack: missing canonical component",
		},

		{
			"app:",
			nil,
			"invalid tack: missing canonical component",
		},
	}

	for _, row := range tab {
		t.Logf("row=%#v", row)

		tack, err := Parse(row.String)

		assert.Equal(t, row.Tack, tack)

		if err != nil {
			assert.Equal(t, row.Error, err.Error())
		} else {
			assert.Equal(t, row.Error, "")
		}
	}
}

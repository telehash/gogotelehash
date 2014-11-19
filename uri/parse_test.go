package uri

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	var tab = []struct {
		String string
		URI    *URI
		Error  string
	}{

		{
			"app://user@canonical/session#token",
			&URI{"app", "user", "canonical", "session", "token"},
			"",
		},

		{
			"canonical",
			&URI{"mesh", "", "canonical", "", ""},
			"",
		},

		{
			"user@canonical",
			&URI{"mesh", "user", "canonical", "", ""},
			"",
		},

		{
			"canonical/session#token",
			&URI{"mesh", "", "canonical", "session", "token"},
			"",
		},

		{
			"app://canonical",
			&URI{"app", "", "canonical", "", ""},
			"",
		},

		{
			"app://user@canonical",
			&URI{"app", "user", "canonical", "", ""},
			"",
		},

		{
			"app://canonical/session#token",
			&URI{"app", "", "canonical", "session", "token"},
			"",
		},

		{
			"app://user@/session#token",
			nil,
			"invalid uri: missing canonical component",
		},

		{
			"app://user@",
			nil,
			"invalid uri: missing canonical component",
		},

		{
			"app://",
			nil,
			"invalid uri: missing canonical component",
		},
	}

	for _, row := range tab {
		t.Logf("row=%#v", row)

		uri, err := Parse(row.String)

		assert.Equal(t, row.URI, uri)

		if err != nil {
			assert.Equal(t, row.Error, err.Error())
		} else {
			assert.Equal(t, row.Error, "")
		}
	}
}

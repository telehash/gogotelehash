package testify

import (
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
	"testing"
)

func TestImports(t *testing.T) {
	if assert.Equal(t, 1, 1) != true {
		t.Error("Something is wrong.")
	}
}

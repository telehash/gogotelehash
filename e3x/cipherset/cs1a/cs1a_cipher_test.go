package cs1a

import (
	"testing"

	"github.com/telehash/gogotelehash/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
	tests.Run(t, &cipher{})
}

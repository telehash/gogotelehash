package cs3a

import (
	"testing"

	"github.com/fd/th/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
	tests.Run(t, &cipher{})
}

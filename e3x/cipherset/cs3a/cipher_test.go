package cs3a

import (
	"testing"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
	tests.Run(t, &cipher{})
}

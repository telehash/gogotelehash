package cs3a

import (
	"testing"

	"github.com/telehash/gogotelehash/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
	tests.Run(t, &cipher{})
}

func BenchmarkPacketEncryption(b *testing.B) {
	tests.BenchmarkPacketEncryption(b, &cipher{})
}

func BenchmarkPacketDecryption(b *testing.B) {
	tests.BenchmarkPacketDecryption(b, &cipher{})
}

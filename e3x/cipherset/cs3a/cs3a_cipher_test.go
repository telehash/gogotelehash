package cs3a

import (
	"testing"

	"github.com/telehash/gogotelehash/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
	tests.Run(t, 0x3a)
}

func BenchmarkPacketEncryption(b *testing.B) {
	tests.BenchmarkPacketEncryption(b, 0x3a)
}

func BenchmarkPacketDecryption(b *testing.B) {
	tests.BenchmarkPacketDecryption(b, 0x3a)
}

func BenchmarkMessageEncryption(b *testing.B) {
	tests.BenchmarkMessageEncryption(b, 0x3a)
}

func BenchmarkMessageDecryption(b *testing.B) {
	tests.BenchmarkMessageDecryption(b, 0x3a)
}

func BenchmarkMessageVerification(b *testing.B) {
	tests.BenchmarkMessageVerification(b, 0x3a)
}

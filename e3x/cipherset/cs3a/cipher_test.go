package cs3a

import (
  "crypto/rand"
  "io"
  mathrand "math/rand"
  "testing"

  "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/tests"
)

func TestCipher(t *testing.T) {
  tests.Run(t, &cipher{})
}

func BenchmarkLookupString_Found(b *testing.B) {
  b.StopTimer()
  var (
    a = "0123456789abcdef"
    m = map[string]int{a: 1}
  )

  randMapString(m, 10000)
  b.StartTimer()

  for i := 0; i < b.N; i++ {
    _ = m[a]
  }
}
func BenchmarkLookupByteArray_Found(b *testing.B) {
  b.StopTimer()
  var (
    a = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'}
    m = map[[16]byte]int{a: 1}
  )

  randMapByteArray(m, 10000)
  b.StartTimer()

  for i := 0; i < b.N; i++ {
    _ = m[a]
  }
}

func BenchmarkLookupString_NotFound(b *testing.B) {
  b.StopTimer()
  var (
    a = "0123456789abcdef"
    m = map[string]int{}
  )

  randMapString(m, 10000)
  b.StartTimer()

  for i := 0; i < b.N; i++ {
    _ = m[a]
  }
}
func BenchmarkLookupByteArray_NotFound(b *testing.B) {
  b.StopTimer()
  var (
    a = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'}
    m = map[[16]byte]int{}
  )

  randMapByteArray(m, 10000)
  b.StartTimer()

  for i := 0; i < b.N; i++ {
    _ = m[a]
  }
}

func randMapString(m map[string]int, n int) map[string]int {
  b := make([]byte, 16)
  for i := 0; i < n; i++ {
    io.ReadFull(rand.Reader, b)
    m[string(b)] = mathrand.Int()
  }
  return m
}

func randMapByteArray(m map[[16]byte]int, n int) map[[16]byte]int {
  var b [16]byte
  for i := 0; i < n; i++ {
    io.ReadFull(rand.Reader, b[:])
    m[b] = mathrand.Int()
  }
  return m
}

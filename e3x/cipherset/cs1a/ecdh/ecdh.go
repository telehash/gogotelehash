// Elliptic curve Diffie–Hellman key sharing
package ecdh

import (
	"crypto/elliptic"
	"math/big"
)

// ComputeShared computes the shared key for the private key material priv and
// the x and y public coordinates
func ComputeShared(curve elliptic.Curve, x, y *big.Int, priv []byte) []byte {
	x, _ = curve.ScalarMult(x, y, priv)
	return x.Bytes()
}

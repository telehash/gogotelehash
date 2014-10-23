// Elliptic Curve Compressed Point marshaler
package eccp

import (
	"crypto/elliptic"
	"math/big"
)

// Marshal encodes a ECC Point into it's compressed representation
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 + byte(y.Bit(0))

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)

	return ret
}

// Unmarshal decodes an ECC Point from any representation
//
// https://github.com/kmackay/micro-ecc/blob/1fce01e69c3f3c179cb9b6238391307426c5e887/uECC.c#L1841
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3

	if len(data) != 1+byteLen {
		// wrong length; fallback to uncompressed
		return elliptic.Unmarshal(curve, data)
	}

	if data[0] != 0x02 && data[0] != 0x03 {
		// wrong header; fallback to uncompressed
		return elliptic.Unmarshal(curve, data)
	}

	x = new(big.Int).SetBytes(data[1 : 1+byteLen])

	y = new(big.Int)

	/* y = x^2 */
	y.Mul(x, x)
	y.Mod(y, curve.Params().P)

	/* y = x^2 - 3 */
	y.Sub(y, iTHREE)
	y.Mod(y, curve.Params().P)

	/* y = x^3 - 3x */
	y.Mul(y, x)
	y.Mod(y, curve.Params().P)

	/* y = x^3 - 3x + b */
	y.Add(y, curve.Params().B)
	y.Mod(y, curve.Params().P)

	modSqrt(y, curve, y)

	if y.Bit(0) != uint(data[0]&0x01) {
		y.Sub(curve.Params().P, y)
	}

	return x, y
}

var iTHREE = big.NewInt(3)

// Compute a = sqrt(a) (mod curve_p).
// https://github.com/kmackay/micro-ecc/blob/1fce01e69c3f3c179cb9b6238391307426c5e887/uECC.c#L1685
func modSqrt(z *big.Int, curve elliptic.Curve, a *big.Int) *big.Int {
	p1 := big.NewInt(1)
	p1.Add(p1, curve.Params().P)

	result := big.NewInt(1)

	for i := p1.BitLen() - 1; i > 1; i-- {
		result.Mul(result, result)
		result.Mod(result, curve.Params().P)
		if p1.Bit(i) > 0 {
			result.Mul(result, a)
			result.Mod(result, curve.Params().P)
		}
	}

	z.Set(result)
	return z
}

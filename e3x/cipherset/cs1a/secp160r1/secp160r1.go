// Parameters for the secp160r1 Elliptic curve
package secp160r1

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once
var p160 *elliptic.CurveParams

func initP160() {
	p160 = new(elliptic.CurveParams)
	p160.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffff7fffffff", 16)
	p160.N, _ = new(big.Int).SetString("0100000000000000000001f4c8f927aed3ca752257", 16)
	p160.B, _ = new(big.Int).SetString("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16)
	p160.Gx, _ = new(big.Int).SetString("4a96b5688ef573284664698968c38bb913cbfc82", 16)
	p160.Gy, _ = new(big.Int).SetString("23a628553168947d59dcc912042351377ac5fb32", 16)
	p160.BitSize = 160
}

func P160() elliptic.Curve {
	initonce.Do(initP160)
	return p160
}

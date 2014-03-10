package cs1a

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

var p160 *elliptic.CurveParams

func init() {
	// see http://www.secg.org/collateral/sec2_final.pdf
	// section 2.4.2
	p160 = new(elliptic.CurveParams)
	p160.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16)
	p160.N, _ = new(big.Int).SetString("0100000000000000000001F4C8F927AED3CA752257", 16)
	p160.B, _ = new(big.Int).SetString("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16)
	p160.Gx, _ = new(big.Int).SetString("4A96B5688EF573284664698968C38BB913CBFC82", 16)
	p160.Gy, _ = new(big.Int).SetString("23A628553168947D59DCC912042351377AC5FB32", 16)
	p160.BitSize = 160
}

func GenerateKey(rand io.Reader) (prv, pub []byte, err error) {
	prv, x, y, err := elliptic.GenerateKey(p160, rand)
	if err != nil {
		return err
	}

	pub = elliptic.Marshal(p160, x, y)
	pub = pub[1:]
	return prv, pub, nil
}

package tack

import (
	"bitbucket.org/simonmenke/go-telehash/e3x"
)

func Resolve(tack *Tack) (*e3x.Ident, error) {
	return resolveHTTP(tack)
}

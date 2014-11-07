package uri

import (
	"github.com/telehash/gogotelehash/e3x"
)

func Resolve(uri *URI) (*e3x.Ident, error) {
	return resolveHTTP(uri)
}

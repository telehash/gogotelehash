package base32util

import (
	"encoding/base32"
	"strings"
)

func DecodeString(s string) ([]byte, error) {
	s = strings.ToUpper(s)
	s = addPadding(s)
	return base32.StdEncoding.DecodeString(s)
}

func EncodeToString(src []byte) string {
	return strings.ToLower(removePadding(base32.StdEncoding.EncodeToString(src)))
}

package base32util

import (
	"encoding/base32"
	"strings"
)

var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

func DecodeString(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = addPadding(s)
	return encoding.DecodeString(s)
}

func EncodeToString(src []byte) string {
	return removePadding(encoding.EncodeToString(src))
}

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

func ValidString(s string) bool {
	for _, r := range s {
		// base32 range:
		// abcdefghijklmnopqrstuvwxyz 234567
		if ('a' <= r && r <= 'z') || ('2' <= r && r <= '7') {
			continue
		}

		return false
	}

	return true
}

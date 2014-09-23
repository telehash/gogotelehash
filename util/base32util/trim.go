package base32util

import (
	"strings"
)

func addPadding(s string) string {
	s = removePadding(s)
	rem := len(s) % 8
	if rem == 0 {
		return s
	}
	return s + strings.Repeat("=", 8-rem)
}

func removePadding(s string) string {
	return strings.TrimRight(s, "=")
}

package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

func RandomString(n int) string {
	var (
		buf = make([]byte, n/2+1)
	)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf)[:n]
}

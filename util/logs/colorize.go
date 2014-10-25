package logs

import (
	"hash/crc32"
)

var colors = []string{
	// # normal
	// "\x1b[30m" // black
	"\x1b[31m", // red
	"\x1b[32m", // green
	"\x1b[33m", // yellow
	"\x1b[34m", // blue
	"\x1b[35m", // magenta
	"\x1b[36m", // cyan
	// "\x1b[37m", // white

	// # bold
	// "\x1b[01;30m" // black
	"\x1b[01;31m", // red
	"\x1b[01;32m", // green
	"\x1b[01;33m", // yellow
	"\x1b[01;34m", // blue
	"\x1b[01;35m", // magenta
	"\x1b[01;36m", // cyan
	// "\x1b[01;37m", // white

	// # underline
	// "\x1b[04;30m" // black
	"\x1b[04;31m", // red
	"\x1b[04;32m", // green
	"\x1b[04;33m", // yellow
	"\x1b[04;34m", // blue
	"\x1b[04;35m", // magenta
	"\x1b[04;36m", // cyan
	// "\x1b[04;37m", // white
}

var ncolors = uint32(len(colors))

const reset = "\x1b[0m"

func colorize(term string) string {
	idx := int(crc32.ChecksumIEEE([]byte(term)) % ncolors)
	return colors[idx] + term + reset
}

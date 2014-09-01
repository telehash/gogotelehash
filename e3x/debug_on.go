// +build debug

package e3x

import (
	"log"
)

func tracef(format string, args ...interface{}) {
	log.Printf(format, args...)
}

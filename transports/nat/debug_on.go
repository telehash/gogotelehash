// +build debug

package nat

import (
	"log"
)

func tracef(format string, args ...interface{}) {
	log.Printf(format, args...)
}

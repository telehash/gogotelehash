package chord

import (
	"log"
)

const traceOn = true

func tracef(format string, args ...interface{}) {
	if traceOn {
		log.Printf(format, args...)
	}
}

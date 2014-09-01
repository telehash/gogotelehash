package transports

import (
	"log"
)

const traceOn = false

func tracef(format string, args ...interface{}) {
	if traceOn {
		log.Printf(format, args...)
	}
}

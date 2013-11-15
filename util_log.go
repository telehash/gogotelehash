package telehash

import (
	"github.com/fd/go-util/log"
	"os"
)

var Log = log.Sub(log_level_for("ALL", log.FATAL), "telehash")

func log_level_for(section string, def log.Level) log.Level {
	switch os.Getenv("TH_LOG_" + section) {
	case "default":
		return def
	case "debug":
		return log.DEBUG
	case "info":
		return log.INFO
	case "notice":
		return log.NOTICE
	case "warn":
		return log.WARN
	case "error":
		return log.ERROR
	case "fatal":
		return log.FATAL
	default:
		return def
	}
}

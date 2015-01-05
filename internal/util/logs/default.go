package logs

import (
	"os"

	"github.com/telehash/gogotelehash/hashname"
)

var defaultLogger = New(os.Stdout)

func ResetLogger() {
	defaultLogger = New(os.Stderr)
	disabledMods = map[string]bool{}
}

func DisableLogger() {
	defaultLogger = nil
}

func Module(name string) *Logger {
	return defaultLogger.Module(name)
}

func From(id hashname.H) *Logger {
	return defaultLogger.From(id)
}

func To(id hashname.H) *Logger {
	return defaultLogger.To(id)
}

func ResetTimer() *Logger {
	return defaultLogger.ResetTimer()
}

func Print(args ...interface{}) {
	defaultLogger.Print(args...)
}

func Println(args ...interface{}) {
	defaultLogger.Println(args...)
}

func Printf(format string, args ...interface{}) {
	defaultLogger.Printf(format, args...)
}

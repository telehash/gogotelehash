package logs

import (
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"bitbucket.org/simonmenke/go-telehash/hashname"
)

var disabledMods = map[string]bool{}

type Logger struct {
	module string
	from   string
	to     string
	start  time.Time
	log    *log.Logger
}

func New(out io.Writer) *Logger {
	l := new(Logger)
	l.start = time.Now()
	l.log = log.New(out, "", 0)
	return l
}

func DisableModule(name string) {
	disabledMods[name] = true
}

func (l *Logger) Module(name string) *Logger {
	if l == nil {
		return nil
	}

	if disabledMods[name] {
		return nil
	}

	x := new(Logger)
	*x = *l
	x.module = name
	return x
}

func (l *Logger) From(id hashname.H) *Logger {
	if l == nil {
		return nil
	}

	x := new(Logger)
	*x = *l
	x.from = string(id)[:4]
	return x
}

func (l *Logger) To(id hashname.H) *Logger {
	if l == nil {
		return nil
	}

	x := new(Logger)
	*x = *l
	x.to = string(id)[:4]
	return x
}

func (l *Logger) ResetTimer() *Logger {
	if l == nil {
		return nil
	}

	x := new(Logger)
	*x = *l
	x.start = time.Now()
	return x
}

func (l *Logger) Print(args ...interface{}) {
	if l == nil {
		return
	}

	l.emit(fmt.Sprint(args...))
}

func (l *Logger) Println(args ...interface{}) {
	if l == nil {
		return
	}

	l.emit(fmt.Sprintln(args...))
}

func (l *Logger) Printf(format string, args ...interface{}) {
	if l == nil {
		return
	}

	l.emit(fmt.Sprintf(format, args...))
}

func (l *Logger) emit(msg string) {
	if l == nil {
		return
	}

	if msg == "" {
		return
	}

	var (
		th, tm, ts, tms time.Duration
		from            string
		to              string
		module          string
	)

	{
		d := time.Since(l.start)

		th = d / time.Hour
		d -= th * time.Hour

		tm = d / time.Minute
		d -= tm * time.Minute

		ts = d / time.Second
		d -= ts * time.Second

		tms = d / time.Millisecond
	}

	from = l.from
	if from == "" {
		from = "    " // 4 spaces
	} else {
		from = colorize(from)
	}

	to = l.to
	if to == "" {
		to = "    " // 4 spaces
	} else {
		to = colorize(to)
	}

	module = l.module
	moduleLen := len(module)
	if moduleLen > 0 {
		module = colorize(module)
	}
	if moduleLen < 12 {
		module += strings.Repeat(" ", 12-moduleLen)
	}

	l.log.Printf("\x1B[2;37m%02d:%02d:%02d.%03d |\x1B[0m %s %s \x1B[2;37m|\x1B[0m %s \x1B[2;37m|\x1B[0m %s", th, tm, ts, tms, from, to, module, msg)
}

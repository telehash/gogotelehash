package runloop

type Backlog []*privateCommand

func (bptr *Backlog) RescheduleAll(l *RunLoop) {
	b := *bptr
	if len(b) > 0 {
		*bptr = nil
		for _, cmd := range b {
			err := l.push(cmd)
			if err != nil {
				cmd.cancel(err)
			}
		}
	}
}

func (bptr *Backlog) RescheduleOne(l *RunLoop) {
	b := *bptr
	if len(b) > 0 {
		// get first command
		cmd := b[0]

		// remove from backlog
		copy(b, b[1:])
		b = b[:len(b)-1]
		*bptr = b

		err := l.push(cmd)
		if err != nil {
			cmd.cancel(err)
		}
	}
}

func (bptr *Backlog) CancelAll(err error) {
	b := *bptr
	*bptr = nil

	for _, cmd := range b {
		cmd.cancel(err)
	}
}

func (l *RunLoop) Defer(bptr *Backlog) {
	l.defered = true
	*bptr = append(*bptr, l.current_cmd)
}

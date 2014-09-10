package mux

import (
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*muxer)(nil)
)

type Config []transports.Config

type muxer struct {
	transports []transports.Transport
}

func (c Config) Open() (transports.Transport, error) {
	m := &muxer{}

	for _, f := range c {
		t, err := f.Open()
		if err != nil {
			return nil, err
		}

		m.transports = append(m.transports, t)
	}

	return m, nil
}

func (m *muxer) Run(w <-chan transports.WriteOp, r chan<- transports.ReadOp, e chan<- events.E) <-chan struct{} {
	var (
		done = make(chan struct{})
		tws  = make([]chan transports.WriteOp, 0, len(m.transports))
		tds  = make([]<-chan struct{}, 0, len(m.transports))
	)

	for _, t := range m.transports {
		tw := make(chan transports.WriteOp)
		td := t.Run(tw, r, e)
		tws = append(tws, tw)
		tds = append(tds, td)
	}

	go m.dispatch(w, tws)
	go m.wait_for_done(done, tds)

	return done
}

func (m *muxer) dispatch(w <-chan transports.WriteOp, tws []chan transports.WriteOp) {
	defer func() {
		for _, tw := range tws {
			close(tw)
		}
	}()

	var (
		cErr chan error
		sent bool
	)

	for op := range w {
		op.C, cErr = make(chan error), op.C
		sent = false

		for _, tw := range tws {
			tw <- op
			err := <-op.C
			if err == transports.ErrInvalidAddr {
				continue
			}
			cErr <- err
			sent = true
			break
		}

		if !sent {
			cErr <- transports.ErrInvalidAddr
		}
	}
}

func (m *muxer) wait_for_done(done chan struct{}, tds []<-chan struct{}) {
	defer close(done)

	for _, td := range tds {
		<-td
	}
}

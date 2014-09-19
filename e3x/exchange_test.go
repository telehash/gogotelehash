package e3x

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/events"

	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
)

func TestBasicExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("this is a long running test.")
	}

	var (
		assert  = assert.New(t)
		err     error
		cEvents = make(chan events.E)

		A = struct {
			a *Addr
			w chan transports.WriteOp
			r chan transports.ReadOp
			x *Exchange
		}{
			a: makeAddr("A"),
			r: make(chan transports.ReadOp),
			w: make(chan transports.WriteOp),
		}

		B = struct {
			a *Addr
			r chan transports.ReadOp
			w chan transports.WriteOp
			x *Exchange
		}{
			a: makeAddr("B"),
			r: make(chan transports.ReadOp),
			w: make(chan transports.WriteOp),
		}
	)

	go events.Log(nil, cEvents)
	go pipeTransport(A.r, B.w)

	A.x, err = newExchange(A.a, B.a, nil, cipherset.ZeroToken, A.w, A.r, cEvents, nil)
	assert.NoError(err)
	go A.x.run()

	go func() {
		var (
			op        = <-A.w
			handshake cipherset.Handshake
			token     cipherset.Token
			err       error
		)

		// detect handshake
		assert.Equal(0, op.Msg[0])
		assert.Equal(1, op.Msg[1])
		assert.Equal(0x3a, op.Msg[2])
		handshake, err = cipherset.DecryptHandshake(0x3a, B.a.keys[0x3a], op.Msg[3:])
		assert.NoError(err)
		token = cipherset.ExtractToken(op.Msg)

		B.x, err = newExchange(B.a, nil, handshake, token, B.w, B.r, cEvents, nil)
		assert.NoError(err)
		go B.x.run()

		if B.x != nil {
			go pipeTransport(B.r, A.w)

			B.r <- transports.ReadOp{Msg: op.Msg, Src: op.Dst}
			op.C <- nil
		}
	}()

	_, _ = <-A.x.done()
	_, _ = <-B.x.done()
}

func makeAddr(name string) *Addr {
	key, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		panic(err)
	}

	addr, err := NewAddr(cipherset.Keys{0x3a: key}, nil, []transports.Addr{
		MockAddr(fmt.Sprintf("%s-%s", name, "1")),
		MockAddr(fmt.Sprintf("%s-%s", name, "2")),
		MockAddr(fmt.Sprintf("%s-%s", name, "3")),
	})
	if err != nil {
		panic(err)
	}

	return addr
}

func pipeTransport(r chan<- transports.ReadOp, w <-chan transports.WriteOp) {
	var (
		q      []transports.ReadOp
		closed bool
	)

	for {
		var (
			rr  = r
			qop transports.ReadOp
		)

		if len(q) == 0 && closed {
			break
		}

		if len(q) > 0 {
			qop = q[0]
		} else {
			rr = nil
		}

		select {

		case op, open := <-w:
			if !open {
				w = nil
				closed = true
			} else {
				op.C <- nil
				q = append(q, transports.ReadOp{Msg: op.Msg, Src: op.Dst})
			}

		case rr <- qop:
			if len(q) > 1 {
				copy(q, q[1:])
			}
			q = q[:len(q)-1]

		}
	}
}

type MockAddr string

func (m MockAddr) Network() string {
	return "mock"
}

func (m MockAddr) String() string {
	data, err := m.MarshalJSON()
	if err != nil {
		panic(err)
	}

	return string(data)
}

func (m MockAddr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}{
		Type: "mock",
		Name: string(m),
	}

	return json.Marshal(&desc)
}

func (a MockAddr) Equal(x transports.Addr) bool {
	b, ok := x.(MockAddr)
	if !ok {
		return false
	}
	return a == b
}

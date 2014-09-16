package e3x

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/transports"

	_ "bitbucket.org/simonmenke/go-telehash/e3x/cipherset/cs3a"
)

func TestBasicExchange(t *testing.T) {
	var (
		assert = assert.New(t)

		A = struct {
			a *Addr
			w chan transports.WriteOp
			r chan transports.ReadOp
			x *exchange
		}{
			a: makeAddr(),
			r: make(chan transports.ReadOp),
			w: make(chan transports.WriteOp),
		}

		B = struct {
			a *Addr
			r chan transports.ReadOp
			w chan transports.WriteOp
			x *exchange
		}{
			a: makeAddr(),
			r: make(chan transports.ReadOp),
			w: make(chan transports.WriteOp),
		}
	)

	go pipeTransport(A.r, B.w)

	A.x = newExchange(B.a.Hashname(), cipherset.ZeroToken, A.w, A.r)
	go A.x.run()

	go func() {
		var (
			op    = <-A.w
			token cipherset.Token
		)

		// detect handshake
		assert.Equal(0, op.Msg[0])
		assert.Equal(1, op.Msg[1])
		assert.Equal(0x3a, op.Msg[2])
		token = cipherset.ExtractToken(op.Msg)

		B.x = newExchange(A.a.Hashname(), token, B.w, B.r)
		go pipeTransport(B.r, A.w)
		go B.x.run()
	}()

	_, _ = <-A.x.done()
	_, _ = <-B.x.done()
}

func makeAddr() *Addr {
	key, err := cipherset.GenerateKey(0x3a)
	if err != nil {
		panic(err)
	}

	addr, err := NewAddr(cipherset.Keys{0x3a: key}, nil, nil)
	if err != nil {
		panic(err)
	}

	return addr
}

func pipeTransport(r chan<- transports.ReadOp, w <-chan transports.WriteOp) {
	for op := range w {
		r <- transports.ReadOp{Msg: op.Msg, Src: op.Dst}
		op.C <- nil
	}
}

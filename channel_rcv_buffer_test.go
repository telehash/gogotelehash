package telehash

import (
	"fmt"
	"io"
	"testing"
	"time"
)

func TestBufRcvIdeal(t *testing.T) {
	buf := make_channel_rcv_buffer()

	buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
	buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 1}})
	buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 2, End: true}})

	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 0}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 1}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 2, End: true}}, nil)
	expect_pkt(t, buf, nil, io.EOF)
	expect_pkt(t, buf, nil, io.EOF)
}

func TestBufRcvWrongOrder(t *testing.T) {
	buf := make_channel_rcv_buffer()

	go func() {
		expect_miss(t, buf, -1, []int{})

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 2}})
		expect_miss(t, buf, 2, []int{0, 1})

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
		expect_miss(t, buf, 2, []int{1})

		time.Sleep(10 * time.Millisecond)

		if buf.received_end() {
			t.Fatal("expected to not have received an .End pkt")
		}

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}})
		expect_miss(t, buf, 3, []int{1})

		if !buf.received_end() {
			t.Fatal("expected to have received an .End pkt")
		}

		time.Sleep(10 * time.Millisecond)

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 1}})
		expect_miss(t, buf, 3, []int{})
	}()

	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 0}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 1}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 2}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}}, nil)
	expect_pkt(t, buf, nil, io.EOF)
	expect_pkt(t, buf, nil, io.EOF)
}

func TestBufRcvDuplicates(t *testing.T) {
	buf := make_channel_rcv_buffer()

	go func() {
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 2}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})

		time.Sleep(10 * time.Millisecond)

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 1}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 4}})
	}()

	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 0}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 1}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 2}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}}, nil)
	expect_pkt(t, buf, nil, io.EOF)
	expect_pkt(t, buf, nil, io.EOF)
}

func TestBufRcvDeadline(t *testing.T) {
	buf := make_channel_rcv_buffer()

	go func() {
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 2}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})

		time.Sleep(50 * time.Millisecond)

		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 0}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 1}})
		buf.put(&pkt_t{hdr: pkt_hdr_t{Seq: 4}})
	}()

	buf.set_deadline(time.Now().Add(10 * time.Millisecond))

	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 0}}, nil)
	expect_pkt(t, buf, nil, ErrTimeout)
	expect_pkt(t, buf, nil, ErrTimeout)
	expect_pkt(t, buf, nil, ErrTimeout)
	expect_pkt(t, buf, nil, ErrTimeout)
	expect_pkt(t, buf, nil, ErrTimeout)

	buf.set_deadline(time.Time{})

	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 1}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 2}}, nil)
	expect_pkt(t, buf, &pkt_t{hdr: pkt_hdr_t{Seq: 3, End: true}}, nil)
	expect_pkt(t, buf, nil, io.EOF)
	expect_pkt(t, buf, nil, io.EOF)
}

func expect_pkt(t *testing.T, buf *channel_rcv_buffer_t, a *pkt_t, aerr error) {
	b, berr := buf.get()
	if a == nil && b != nil {
		panic(fmt.Sprintf("unexpected pkt expected=<nil> actual=%d", b.hdr.Seq))
	}
	if a != nil && b == nil {
		panic(fmt.Sprintf("missing pkt expected=%d actual=<nil>", a.hdr.Seq))
	}
	if aerr == nil && berr != nil {
		panic(fmt.Sprintf("unexpected err expected=<nil> actual=%s", berr))
	}
	if aerr != nil && berr == nil {
		panic(fmt.Sprintf("missing err expected=%s actual=<nil>", aerr))
	}
	if a != nil {
		if b.hdr.Seq != a.hdr.Seq {
			panic(fmt.Sprintf("wrong .Seq expected=%d actual=%d", a.hdr.Seq, b.hdr.Seq))
		}
		if b.hdr.End != a.hdr.End {
			panic(fmt.Sprintf("wrong .End expected=%d actual=%d", a.hdr.End, b.hdr.End))
		}
	}
	if aerr != nil {
		if berr.Error() != aerr.Error() {
			panic(fmt.Sprintf("wrong err expected=%d actual=%d", aerr, berr))
		}
	}
}

func expect_miss(t *testing.T, buf *channel_rcv_buffer_t, ack int, miss []int) {
	a_ack, a_miss := buf.inspect()

	if a_ack != ack {
		panic(fmt.Sprintf("wrong .Ack expected=%d actual=%d", ack, a_ack))
	}

	if len(a_miss) != len(miss) {
		panic(fmt.Sprintf("wrong .Miss expected=%+v actual=%+v", miss, a_miss))
	}

	for i, s := range miss {
		if s != a_miss[i] {
			panic(fmt.Sprintf("wrong .Miss expected=%+v actual=%+v", miss, a_miss))
		}
	}
}

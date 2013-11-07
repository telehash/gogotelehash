package telehash

import (
	"io"
	"sort"
	"sync"
	"time"
)

type channel_rcv_buffer_t struct {
	read_seq         int
	max_seq          int
	miss             []int
	buf              pkt_queue_t
	received_end_pkt bool
	deadline         *time.Timer
	deadline_reached bool

	mtx sync.RWMutex
	cnd *sync.Cond
}

func make_channel_rcv_buffer() *channel_rcv_buffer_t {
	b := &channel_rcv_buffer_t{
		max_seq: -1,
		buf:     make(pkt_queue_t, 0, 100), // pre allocate memory
		miss:    make([]int, 0, 100),       // pre allocate memory
	}

	b.deadline = time.AfterFunc(10*time.Millisecond, b._mark_deadline_reached)
	b.deadline.Stop()
	b.cnd = sync.NewCond(&b.mtx)

	return b
}

func (c *channel_rcv_buffer_t) inspect() (ack int, miss []int) {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	var (
		m []int
	)

	if len(c.miss) > 0 {
		m = make([]int, len(c.miss))
		copy(m, c.miss)
	}

	return c.max_seq, m
}

func (c *channel_rcv_buffer_t) received_end() bool {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.received_end_pkt
}

// blocks until the next pkt is ready
// returns nil when the stream has ended
func (c *channel_rcv_buffer_t) get() (*pkt_t, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for !c._ended() && !c._pkt_available() && !c.deadline_reached {
		c.cnd.Wait()
	}

	var (
		pkt *pkt_t
		err error
	)

	if c.deadline_reached {
		err = ErrTimeout
	} else if c._ended() {
		err = io.EOF
	} else {
		c.read_seq++
		n := len(c.buf)
		pkt = c.buf[n-1]
		c.buf = c.buf[:n-1]
	}

	// signal next blocked reader (if any)
	c.cnd.Signal()

	return pkt, err
}

// puts a new pkt on the queue
func (c *channel_rcv_buffer_t) put(pkt *pkt_t) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c._should_drop(pkt) {
		return
	}

	// mark end pkt
	if pkt.hdr.End {
		c.received_end_pkt = true
	}

	// mark new max seq
	if pkt.hdr.Seq > c.max_seq {
		c.max_seq = pkt.hdr.Seq
	}

	// push pkt
	c.buf = append(c.buf, pkt)
	sort.Sort(c.buf)

	// update miss list
	c._update_miss_list()

	// signal next blocked reader (if any)
	c.cnd.Signal()
}

func (c *channel_rcv_buffer_t) set_deadline(t time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if !t.IsZero() {
		c.deadline.Reset(t.Sub(time.Now()))
	}

	c.deadline_reached = false
}

func (c *channel_rcv_buffer_t) _mark_deadline_reached() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.deadline_reached = true
	// signal next blocked reader (if any)
	c.cnd.Signal()
}

func (c *channel_rcv_buffer_t) _update_miss_list() {
	c.miss = c.miss[:0]

	n := len(c.buf)
	last := c.read_seq // last unknown seq

	for i := n - 1; i >= 0; i-- {
		next := c.buf[i].hdr.Seq
		for j := last; j < next; j++ {
			c.miss = append(c.miss, j)
		}
		last = next + 1
	}
}

func (c *channel_rcv_buffer_t) _should_drop(pkt *pkt_t) bool {
	var (
		seq = pkt.hdr.Seq
		n   = len(c.buf)
	)

	// already read?
	if c.read_seq > seq {
		return true
	}

	// was send after end pkt?
	if seq > c.max_seq {
		if c.received_end_pkt {
			return true
		} else {
			return false
		}
	}

	// already in buf
	// not the larger seq is at lower index
	if n == 0 {
		return false // buf is empty
	}

	idx := sort.Search(n, func(i int) bool {
		return c.buf[i].hdr.Seq <= seq
	})

	if idx == n {
		return false // not found
	}

	if c.buf[idx].hdr.Seq == seq {
		return true // already have seq
	}

	return false
}

func (c *channel_rcv_buffer_t) _ended() bool {
	return c.read_seq > c.max_seq && c.received_end_pkt
}

func (c *channel_rcv_buffer_t) _pkt_available() bool {
	n := len(c.buf)
	return n > 0 && c.read_seq == c.buf[n-1].hdr.Seq
}

// A pkt heap
type pkt_queue_t []*pkt_t

func (pq pkt_queue_t) Len() int { return len(pq) }

func (pq pkt_queue_t) Less(i, j int) bool {
	return pq[i].hdr.Seq > pq[j].hdr.Seq
}

func (pq pkt_queue_t) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

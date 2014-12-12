package kademlia

import (
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/telehash/gogotelehash/hashname"
)

type Seek struct {
	target              Key
	numLocalCandidates  int
	numQueuedCandidates int
	numParallelSeeks    int
	numResults          int

	table         *table
	driver        Driver
	wg            sync.WaitGroup
	cntQueries    uint32
	cntCandidates uint32
}

type SeekOption func(*Seek) error

func (op *Seek) setOptions(options ...SeekOption) error {
	for _, opt := range options {
		if err := opt(op); err != nil {
			return err
		}
	}
	return nil
}

func NumLocalCandidates(n int) SeekOption {
	return func(op *Seek) error {
		if n < 0 {
			n = 0
		}
		op.numLocalCandidates = n
		return nil
	}
}

func NumQueuedCandidates(n int) SeekOption {
	return func(op *Seek) error {
		if n < 0 {
			n = 0
		}
		op.numQueuedCandidates = n
		return nil
	}
}

func NumParallelSeeks(n int) SeekOption {
	return func(op *Seek) error {
		if n < 0 {
			n = 0
		}
		op.numParallelSeeks = n
		return nil
	}
}

func NumResults(n int) SeekOption {
	return func(op *Seek) error {
		if n < 0 {
			n = 0
		}
		op.numResults = n
		return nil
	}
}

func (op *Seek) seek() []hashname.H {
	var (
		results <-chan []hashname.H
		peers   <-chan hashname.H
		reenter = make(chan hashname.H, 1)
		start   = time.Now()
	)

	if op.numLocalCandidates == 0 {
		op.numLocalCandidates = 25
	}

	if op.numQueuedCandidates == 0 {
		op.numQueuedCandidates = 100
	}

	if op.numParallelSeeks == 0 {
		op.numParallelSeeks = 8
	}

	if op.numResults == 0 {
		op.numResults = 3
	}

	peers = op.querySelfForPeers()
	{ // this is the concurrent/parallel inner loop
		// It breaks when:
		// - the n closest nodes to target are found
		// - deadline reached
		// The n closest nodes to target are found:
		// - when the queue is empty and when there are no running lookups
		peers = op.reenterSeekJoin(peers, reenter)
		peers = op.deduplicatePeers(peers)
		peers = op.prioritizePeers(peers, reenter)
		peers = op.queryPeersForMorePeers(peers, reenter)
		peers = op.reenterSeekSplit(peers, reenter)
	}
	results = op.collectClosestPeers(peers)
	out := <-results

	log.Printf("SEEK %x duration=%s queries=%d candidates=%d", op.target, time.Since(start), op.cntQueries, op.cntCandidates)

	return out
}

func (op *Seek) querySelfForPeers() <-chan hashname.H {
	out := make(chan hashname.H)
	op.wg.Add(1)
	go func() {
		defer close(out)
		defer op.wg.Done()

		peers := op.table.findKey(op.target, uint(op.numLocalCandidates))

		for _, peer := range peers {
			out <- peer
		}
	}()
	return out
}

func (op *Seek) reenterSeekJoin(in, reenter <-chan hashname.H) <-chan hashname.H {
	var (
		out    = make(chan hashname.H)
		closer = make(chan struct{})
	)

	go func() {
		op.wg.Wait()
		close(closer)

		// flush reenter
		for _ = range reenter {
		}
	}()

	op.wg.Add(1)

	go func() {
		defer close(out)

		for {
			if in == nil && reenter == nil {
				break
			}

			select {

			case <-closer:
				return

			case peer, ok := <-in:
				if ok {
					out <- peer
				} else {
					op.wg.Done()
					in = nil
				}

			case peer, ok := <-reenter:
				if ok {
					out <- peer
				} else {
					reenter = nil
				}

			}
		}
	}()
	return out
}

func (op *Seek) reenterSeekSplit(in <-chan hashname.H, reenter chan<- hashname.H) <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)
		defer close(reenter)

		for peer := range in {
			reenter <- peer
			out <- peer
		}
	}()
	return out
}

func (op *Seek) deduplicatePeers(in <-chan hashname.H) <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)

		var (
			cache = map[hashname.H]bool{}
		)

		for peer := range in {
			done, found := cache[peer]

			if !found {
				atomic.AddUint32(&op.cntCandidates, 1)
				op.wg.Add(1)
				cache[peer] = false
				out <- peer
				continue
			}

			if !done {
				op.wg.Done()
				cache[peer] = true
				continue
			}
		}
	}()
	return out
}

func (op *Seek) prioritizePeers(in <-chan hashname.H, reenter chan<- hashname.H) <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)

		var (
			queue seekQueue
		)

	LOOP:
		for {
			var (
				outSelect chan hashname.H
				head      hashname.H
			)

			if len(queue) == 0 {
				// queue is empty don't allow select on out
				if in == nil {
					// inbound channel was closed
					break LOOP
				}
			} else {
				// allow selecting the head
				outSelect = out
				head = queue[0].hashname
			}

			select {

			case peer, ok := <-in:
				if !ok {
					in = nil
					goto LOOP
				}

				item := &seekQueueItem{
					hashname: peer,
					distance: keyDistance(peer, op.target[:]),
				}

				queue = append(queue, item)
				sort.Sort(queue)
				if len(queue) > op.numQueuedCandidates {
					// reenter the dropped peers (this maintains the wait group)
					for _, item := range queue[op.numQueuedCandidates:] {
						reenter <- item.hashname
					}

					// trim the queue
					queue = queue[:op.numQueuedCandidates]
				}

			case outSelect <- head:
				copy(queue, queue[1:])
				queue = queue[:len(queue)-1]

			}
		}
	}()
	return out
}

func (op *Seek) queryPeersForMorePeers(in <-chan hashname.H, reenter chan<- hashname.H) <-chan hashname.H {
	var (
		out = make(chan hashname.H)
		wg  = &sync.WaitGroup{}
	)

	// closer
	go func() {
		wg.Wait()
		close(out)
	}()

	// workers
	for i := 0; i < op.numParallelSeeks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for peer := range in {

				atomic.AddUint32(&op.cntQueries, 1)

				l, err := op.driver.Seek(peer, op.target)
				if err != nil {
					// reenter the dropped peers (this maintains the wait group)
					reenter <- peer
					continue
				}

				for _, candidate := range l {
					op.table.addCandidate(candidate, peer)
				}

				// pass on peer
				out <- peer

				// pass on candidates
				for _, candidate := range l {
					out <- candidate
				}

			}
		}()
	}

	return out
}

func (op *Seek) collectClosestPeers(in <-chan hashname.H) <-chan []hashname.H {
	var out = make(chan []hashname.H)
	go func() {
		defer close(out)

		var (
			buffer = make(seekQueue, 0, op.numResults+1)
			result = make([]hashname.H, 0, op.numResults)
		)

		for peer := range in {
			buffer = append(buffer, &seekQueueItem{
				hashname: peer,
				distance: keyDistance(peer, op.target[:]),
			})

			sort.Sort(buffer)

			if len(buffer) > op.numResults {
				buffer = buffer[:op.numResults]
			}
		}

		for _, item := range buffer {
			result = append(result, item.hashname)
		}

		out <- result
	}()
	return out
}

type seekQueue []*seekQueueItem

type seekQueueItem struct {
	hashname hashname.H
	distance keyDist
}

func (s seekQueue) Len() int           { return len(s) }
func (s seekQueue) Less(i, j int) bool { return distanceLess(s[i].distance, s[j].distance) }
func (s seekQueue) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

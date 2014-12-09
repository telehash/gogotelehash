package kademlia

import (
	"sort"
	"sync"

	"github.com/telehash/gogotelehash/hashname"
)

type Seek struct {
	target              hashname.H
	numLocalCandidates  int
	numQueuedCandidates int
	numParallelSeeks    int
	numResults          int
}

// maintenance:
// - seek self with peers
//   if no new candidates break
// - connect to candidates
//   if new peers continue seek with new peers
//
// - seek random with peers
//   if no new candidates break
// - connect to candidates
//   if new peers continue seek with new peers

func (op *Seek) seek() {
	var (
		results <-chan []hashname.H
		peers   <-chan hashname.H
		reenter = make(chan hashname.H)
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
		peers = op.prioritizePeers(peers)
		// peers = op.cancelableStream(peers, cancel)
		peers = op.queryPeersForMorePeers(peers)
		peers = op.reenterSeekSplit(peers, reenter)
	}
	results = op.collectClosestPeers(peers)
	return <-results
}

func (op *Seek) querySelfForPeers() <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)

		peers := mod.table.findNode(op.target, op.numLocalCandidates)

		for _, peer := range peers {
			out <- peer
		}
	}()
	return out
}

func (op *Seek) reenterSeekJoin(in, reenter <-chan hashname.H) <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)

		for {
			if in == nil && reenter == nil {
				break
			}

			select {

			case peer, ok := <-in:
				if ok {
					out <- peer
				} else {
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
			if !cache[peer] {
				cache[peer] = true
				out <- peer
			}
		}
	}()
	return out
}

func (op *Seek) prioritizePeers(in <-chan hashname.H) <-chan hashname.H {
	out := make(chan hashname.H)
	go func() {
		defer close(out)

		var (
			closedIn bool
			queue    seekQueue
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
					distance: distance(peer, op.target),
				}

				queue = append(queue, item)
				sort.Sort(queue)
				if len(queue) > op.numQueuedCandidates {
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

func (op *Seek) queryPeersForMorePeers(in <-chan hashname.H) <-chan hashname.H {
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

				x, err := mod.e.Dial(identifier)
				if err != nil {
					continue
				}

				l, err := op.mod.seekFunc(op.target, x)
				if err != nil {
					continue
				}

				for _, candidate := range l {
					op.mod.table.addCandidate(candidate, peer)
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
			buffer = make(seekQueue, op.numResults+1)
			result = make([]hashname.H, 0, op.numResults)
		)

		for peer := range in {
			buffer = append(buffer, &seekQueueItem{
				hashname: peer,
				distance: distance(op.target, peer),
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
	distance [keyLen]byte
}

func (s seekQueue) Len() int           { return len(s) }
func (s seekQueue) Less(i, j int) bool { return distanceLess(s[i].distance, s[j].distance) }
func (s seekQueue) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

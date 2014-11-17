package kademlia

import (
	"container/list"
	"fmt"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/util/base32util"
)

const (
	numBuckets             = 256
	maxPeers               = 32
	maxCandidates          = 128
	maxRoutersPerCandidate = 5
)

type table struct {
	localHashname hashname.H
	buckets       [numBuckets]*bucket
}

type bucket struct {
	id         int
	peers      list.List
	candidates list.List
}

type activePeer struct {
	peerInfo
	tag mesh.Tag
}

type candidatePeer struct {
	peerInfo
	routers []hashname.H
}

type peerInfo struct {
	bucket   int
	distance [32]byte
	hashname hashname.H
}

func (t *table) init() {
	for i := range t.buckets {
		t.buckets[i] = &bucket{id: i}
	}
}

func (t *table) nextCandidate() *candidatePeer {
	for _, b := range t.buckets {

		// bucket is full
		if b.peers.Len() == maxPeers {
			continue
		}

		// no candidates
		if b.candidates.Len() == 0 {
			continue
		}

		// return first candidate
		// also remove it from the candidate list
		return b.candidates.Remove(b.candidates.Front()).(*candidatePeer)
	}

	return nil
}

func (t *table) activatePeer(hn hashname.H, tag mesh.Tag) {
	var (
		dist      = distance(t.localHashname, hn)
		bucketIdx = bucketFromDistance(dist)
		bucket    *bucket
	)

	// cannot link self
	if bucketIdx < 0 {
		tag.Release()
		return
	}

	bucket = t.buckets[bucketIdx]

	// attempt to update peer
	for e := bucket.peers.Front(); e != nil; e = e.Next() {
		i := e.Value.(*activePeer)
		if i.hashname == hn {
			i.tag.Release()
			i.tag = tag
			return
		}
	}

	// too many peers
	if bucket.peers.Len() >= maxPeers {
		tag.Release()
		return
	}

	// add peer
	bucket.peers.PushBack(&activePeer{
		peerInfo: peerInfo{
			distance: dist,
			bucket:   bucketIdx,
			hashname: hn,
		},
		tag: tag,
	})
}

func (t *table) deactivatePeer(hn hashname.H) {
	var (
		dist      = distance(t.localHashname, hn)
		bucketIdx = bucketFromDistance(dist)
		bucket    *bucket
	)

	// cannot unlink self
	if bucketIdx < 0 {
		tag.Release()
		return
	}

	bucket = t.buckets[bucketIdx]

	for e := bucket.peers.Front(); e != nil; e = e.Next() {
		v := e.Value.(*activePeer)
		if v.hashname == hn {
			v.tag.Release()
			bucket.peers.Remove(e)
			break
		}
	}

	for e := bucket.candidates.Front(); e != nil; e = e.Next() {
		v := e.Value.(*candidatePeer)
		if v.hashname == hn {
			bucket.candidates.Remove(e)
			break
		}
	}
}

func (t *table) addCandidate(hn hashname.H, router hashname.H) {
	var (
		dist      = distance(t.localHashname, hn)
		bucketIdx = bucketFromDistance(dist)
		bucket    *bucket
	)

	if bucketIdx < 0 {
		// cannot add self
		return
	}

	bucket = t.buckets[bucketIdx]

	// ignore if active peer
	for e := bucket.peers.Front(); e != nil; e = e.Next() {
		c := e.Value.(*activePeer)
		if c.hashname == hn {
			return
		}
	}

	// attempt to update
	for e := bucket.candidates.Front(); e != nil; e = e.Next() {
		c := e.Value.(*candidatePeer)
		if c.hashname == hn {

			// add router
			for _, r := range c.routers {
				if r != router {
					c.routers = append(c.routers, r)
				}
			}

			// trim routers
			if len(c.routers) > maxRoutersPerCandidate {
				c.routers = c.routers[:maxRoutersPerCandidate]
			}

			return
		}
	}

	// attempt to add
	if bucket.candidates.Len() < maxCandidates {
		bucket.candidates.PushBack(&candidatePeer{
			peerInfo: peerInfo{
				distance: dist,
				bucket:   bucketIdx,
				hashname: hn,
			},
			routers: []hashname.H{router},
		})
	}
}

func distance(a, b hashname.H) [32]byte {
	var (
		aData []byte
		bData []byte
		err   error
		d     [32]byte
	)

	aData, err = base32util.DecodeString(string(a))
	if err != nil {
		return d
	}

	bData, err = base32util.DecodeString(string(b))
	if err != nil {
		return d
	}

	if len(aData) != len(bData) {
		return d
	}

	if len(aData) != 32 {
		return d
	}

	for i, x := range aData {
		d[i] = x ^ bData[i]
	}

	return d
}

func bucketFromDistance(distance [32]byte) int {
	var (
		b = 0
		x byte
	)

	for _, x = range distance {
		if x > 0 {
			break
		}
		b += 8
	}

	if b == (32 * 8) {
		return -1
	}

	switch {
	case (x >> 7) > 0: // 1xxx xxxx
		b += 0
	case (x >> 6) > 0: // 01xx xxxx
		b += 1
	case (x >> 5) > 0: // 001x xxxx
		b += 2
	case (x >> 4) > 0: // 0001 xxxx
		b += 3
	case (x >> 3) > 0: // 0000 1xxx
		b += 4
	case (x >> 2) > 0: // 0000 01xx
		b += 5
	case (x >> 1) > 0: // 0000 001x
		b += 6
	default: // 0000 0001
		b += 7
	}

	return b
}

func (c *table) String() string {
	return fmt.Sprintf("{%s}", c.buckets)
}

func (c *bucket) String() string {
	peers := make([]string, 0, c.peers.Len())
	candidates := make([]string, 0, c.candidates.Len())

	for e := c.peers.Front(); e != nil; e = e.Next() {
		i := e.Value.(*activePeer)
		peers = append(peers, i.String())
	}

	for e := c.candidates.Front(); e != nil; e = e.Next() {
		i := e.Value.(*candidatePeer)
		candidates = append(candidates, i.String())
	}

	return fmt.Sprintf("{id:%d (%d)%s (%d)%s}", c.id, c.peers.Len(), peers, c.candidates.Len(), candidates)
}

func (c *peerInfo) String() string {
	return c.hashname.String()[:5]
}

package kademlia

import (
	"bytes"
	"container/list"
	"fmt"
	"sort"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/util/base32util"
)

const (
	keyLen                 = 32
	numBuckets             = keyLen * 8
	maxPeers               = 32
	maxCandidates          = 128
	maxRoutersPerCandidate = 5
	defaultLookupSize      = 32
)

type table struct {
	localHashname hashname.H
	buckets       [numBuckets]*bucket
}

type bucket struct {
	id         int
	peers      list.List
	candidates list.List
	pending    list.List
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
	distance [keyLen]byte
	hashname hashname.H
}

func (t *table) init() {
	for i := range t.buckets {
		t.buckets[i] = &bucket{id: i}
	}
}

func (t *table) findKey(key [keyLen]byte, n uint) []hashname.H {
	var (
		dist      = keyDistance(t.localHashname, key[:])
		bucketIdx = bucketFromDistance(dist)
		bucket    *bucket
		offset    = 1
		peers     []*activePeer
		out       []hashname.H
	)

	if n == 0 {
		n = defaultLookupSize
	}

	if bucketIdx < 0 {
		bucketIdx = 0
	}

	peers = make([]peerInfo, 0, n+(3*maxPeers))

	{ // find initial bucket
		bucket = t.buckets[bucketIdx]

		for e := bucket.peers.Front(); e != nil; e = e.Next() {
			v := e.Value.(*activePeer)
			if v != nil {
				peers = append(peers, v.peerInfo)
			}
		}
	}

	// add additional peers
	for len(peers) < n && offset < numBuckets {

		// lower bucket
		idx := bucketIdx - offset
		if idx >= 0 {
			bucket = t.buckets[idx]

			for e := bucket.peers.Front(); e != nil; e = e.Next() {
				v := e.Value.(*activePeer)
				if v != nil {
					peers = append(peers, v.peerInfo)
				}
			}
		}

		// higher bucket
		idx = bucketIdx + offset
		if idx < numBuckets {
			bucket = t.buckets[idx]

			for e := bucket.peers.Front(); e != nil; e = e.Next() {
				v := e.Value.(*activePeer)
				if v != nil {
					peers = append(peers, v.peerInfo)
				}
			}
		}

		// increase offset
		offset++
	}

	// determine the distance of each peer to the key
	for i, peer := range peers {
		peer.distance = keyDistance(peer.hashname, key[:])
		peers[i] = peer
	}

	// sort by distance
	sort.Sort(peerInfoByDistance(peers))

	// trim
	if len(peers) > n {
		peers = peers[:n]
	}

	out = make([]hashname.H, len(peers))
	for i, peer := range peers {
		out[i] = peer.hashname
	}

	return out
}

func (t *table) findNode(hn hashname.H, n uint) []hashname.H {
	var (
		keyData []byte
		err     error
		key     [keyLen]byte
	)

	keyData, err = base32util.DecodeString(string(hn))
	if err != nil {
		return nil
	}
	if len(keyData) != keyLen {
		return nil
	}

	copy(key[:], keyData)

	return t.findKey(key, n)
}

func (t *table) nextCandidate() *candidatePeer {
	for _, b := range t.buckets {

		// bucket is full or will be full soon
		if (b.peers.Len() + b.pending.Len()) == maxPeers {
			continue
		}

		// no candidates
		if b.candidates.Len() == 0 {
			continue
		}

		// return first candidate
		// also remove it from the candidate list
		c := b.candidates.Remove(b.candidates.Front()).(*candidatePeer)
		b.pending.PushBack(c)

		return c
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

	// remove from pending list
	for e := bucket.pending.Front(); e != nil; e = e.Next() {
		v := e.Value.(*candidatePeer)
		if v.hashname == hn {
			bucket.pending.Remove(e)
			break
		}
	}

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
		return
	}

	bucket = t.buckets[bucketIdx]

	// remove from peers list
	for e := bucket.peers.Front(); e != nil; e = e.Next() {
		v := e.Value.(*activePeer)
		if v.hashname == hn {
			v.tag.Release()
			bucket.peers.Remove(e)
			break
		}
	}

	// remove from candidates list
	for e := bucket.candidates.Front(); e != nil; e = e.Next() {
		v := e.Value.(*candidatePeer)
		if v.hashname == hn {
			bucket.candidates.Remove(e)
			break
		}
	}

	// remove from pending list
	for e := bucket.pending.Front(); e != nil; e = e.Next() {
		v := e.Value.(*candidatePeer)
		if v.hashname == hn {
			bucket.pending.Remove(e)
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

	// ignore if pending peer
	for e := bucket.pending.Front(); e != nil; e = e.Next() {
		v := e.Value.(*candidatePeer)
		if v.hashname == hn {
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

func distance(a, b hashname.H) [keyLen]byte {
	var (
		bData []byte
		err   error
		d     [keyLen]byte
	)

	bData, err = base32util.DecodeString(string(b))
	if err != nil {
		return d
	}

	return keyDistance(a, bData)
}

func keyDistance(a hashname.H, bData []byte) [keyLen]byte {
	var (
		aData []byte
		err   error
		d     [keyLen]byte
	)

	aData, err = base32util.DecodeString(string(a))
	if err != nil {
		return d
	}

	if len(aData) != len(bData) {
		return d
	}

	if len(aData) != keyLen {
		return d
	}

	for i, x := range aData {
		d[i] = x ^ bData[i]
	}

	return d
}

func bucketFromDistance(distance [keyLen]byte) int {
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

	if b == numBuckets {
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

func distanceLess(a, b [keyLen]byte) bool {
	return bytes.Compare(a[:], b[:]) < 0
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

type peerInfoByDistance []peerInfo

func (s peerInfoByDistance) Len() int           { return len(s) }
func (s peerInfoByDistance) Less(i, j int) bool { return distanceLess(s[i].distance, s[j].distance) }
func (s peerInfoByDistance) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

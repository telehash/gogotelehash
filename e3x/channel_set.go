package e3x

import (
	"sync"
)

type channelSet struct {
	mtx      sync.RWMutex
	channels map[uint32]*Channel
}

func (set *channelSet) Get(id uint32) *Channel {
	var (
		c *Channel
	)

	set.mtx.RLock()
	if set.channels != nil {
		c = set.channels[id]
	}
	set.mtx.RUnlock()

	return c
}

func (set *channelSet) All() []*Channel {
	set.mtx.RLock()

	s := make([]*Channel, 0, len(set.channels))
	for _, c := range set.channels {
		s = append(s, c)
	}
	set.mtx.RUnlock()

	return s
}

func (set *channelSet) Remove(id uint32) bool {
	set.mtx.Lock()
	defer set.mtx.Unlock()

	if set.channels == nil {
		return false
	}

	if set.channels[id] == nil {
		return false
	}

	delete(set.channels, id)
	return true
}

type channelSetAddPromise struct {
	id  uint32
	set *channelSet
}

func (set *channelSet) GetOrAdd(id uint32) (c *Channel, promise *channelSetAddPromise) {
	set.mtx.RLock()
	if set.channels != nil {
		c = set.channels[id]
	}
	set.mtx.RUnlock()

	if c != nil {
		return c, nil
	}

	set.mtx.Lock()
	if set.channels == nil {
		set.channels = make(map[uint32]*Channel)
	}
	c = set.channels[id]
	if c != nil {
		set.mtx.Unlock()
		return c, nil
	}

	// should remain locked (will be unlocked by the promise)
	return nil, &channelSetAddPromise{id, set}
}

func (p *channelSetAddPromise) Add(c *Channel) {
	p.set.channels[p.id] = c
	p.set.mtx.Unlock()
}

func (p *channelSetAddPromise) Cancel() {
	p.set.mtx.Unlock()
}

func (set *channelSet) Add(id uint32, c *Channel) (ok bool) {
	set.mtx.Lock()
	defer set.mtx.Unlock()

	if set.channels == nil {
		set.channels = make(map[uint32]*Channel)
	}

	if set.channels[id] != nil {
		return false
	}

	set.channels[id] = c
	return true
}

func (set *channelSet) Idle() bool {
	set.mtx.RLock()
	idle := true
	if set.channels != nil && len(set.channels) > 0 {
		idle = false
	}
	set.mtx.RUnlock()
	return idle
}

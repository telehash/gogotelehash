package e3x

import (
	"sync"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/hashname"
)

type exchangeSet struct {
	mtx       sync.RWMutex
	exchanges map[hashname.H]*Exchange
	tokens    map[cipherset.Token]*Exchange
}

func (set *exchangeSet) GetWithHashname(h hashname.H) *Exchange {
	if set == nil {
		return nil
	}

	var (
		x *Exchange
	)

	set.mtx.RLock()
	if set.exchanges != nil {
		x = set.exchanges[h]
	}
	set.mtx.RUnlock()

	return x
}

func (set *exchangeSet) GetWithToken(token cipherset.Token) *Exchange {
	if set == nil {
		return nil
	}

	var (
		x *Exchange
	)

	set.mtx.RLock()
	if set.tokens != nil {
		x = set.tokens[token]
	}
	set.mtx.RUnlock()

	return x
}

func (set *exchangeSet) All() []*Exchange {
	if set == nil {
		return nil
	}

	set.mtx.RLock()
	s := make([]*Exchange, 0, len(set.exchanges))
	for _, x := range set.exchanges {
		s = append(s, x)
	}
	set.mtx.RUnlock()

	return s
}

func (set *exchangeSet) Remove(x *Exchange) bool {
	if set == nil {
		return false
	}

	set.mtx.Lock()
	defer set.mtx.Unlock()

	var removed bool

	if set.exchanges != nil {
		for k, xx := range set.exchanges {
			if xx == x {
				removed = true
				delete(set.exchanges, k)
			}
		}
	}

	if set.tokens != nil {
		for k, xx := range set.tokens {
			if xx == x {
				removed = true
				delete(set.tokens, k)
			}
		}
	}

	return removed
}

type exchangeSetAddPromise struct {
	hashname hashname.H
	set      *exchangeSet
}

func (set *exchangeSet) GetOrAdd(h hashname.H) (x *Exchange, promise *exchangeSetAddPromise) {
	if set == nil {
		return nil, nil
	}

	set.mtx.RLock()
	if set.exchanges != nil {
		x = set.exchanges[h]
	}
	set.mtx.RUnlock()

	if x != nil {
		return x, nil
	}

	set.mtx.Lock()
	if set.exchanges == nil {
		set.exchanges = make(map[hashname.H]*Exchange)
	}
	if set.tokens == nil {
		set.tokens = make(map[cipherset.Token]*Exchange)
	}
	x = set.exchanges[h]
	if x != nil {
		set.mtx.Unlock()
		return x, nil
	}

	// should remain locked (will be unlocked by the promise)
	return nil, &exchangeSetAddPromise{h, set}
}

func (p *exchangeSetAddPromise) Add(x *Exchange) {
	p.set.exchanges[p.hashname] = x
	p.set.mtx.Unlock()
}

func (p *exchangeSetAddPromise) Cancel() {
	p.set.mtx.Unlock()
}

func (set *exchangeSet) UpdateTokens(x *Exchange, local, remote cipherset.Token) {
	if set == nil {
		return
	}

	set.mtx.Lock()
	defer set.mtx.Unlock()

	for k, xx := range set.tokens {
		if xx == x {
			delete(set.tokens, k)
		}
	}

	if local != cipherset.ZeroToken {
		set.tokens[local] = x
	}

	if remote != cipherset.ZeroToken {
		set.tokens[remote] = x
	}
}

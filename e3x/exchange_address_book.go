package e3x

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/transports"
)

const (
	cMaxAddressBookEntries = 16
	cNumBackupAddresses    = 3
)

type addressBook struct {
	log *logs.Logger

	mtx         sync.RWMutex
	active      *addressBookEntry
	known       []*addressBookEntry
	unsupported []string
}

const (
	ewma_α = 0.45
)

type addressBookEntry struct {
	Pipe                *Pipe
	Address             net.Addr
	SendHandshakeAt     time.Time
	ReceivedHandshakeAt time.Time
	Added               time.Time
	ExpireAt            time.Time
	Reachable           bool
	IsBackup            bool

	latency time.Duration
	ewma    time.Duration
}

func newAddressBook(log *logs.Logger) *addressBook {
	return &addressBook{log: log.Module("addrbook")}
}

func (book *addressBook) ActiveConnection() *Pipe {
	book.mtx.RLock()
	e := book.active
	book.mtx.RUnlock()

	if e == nil {
		return nil
	}

	return e.Pipe
}

func (book *addressBook) KnownAddresses() []net.Addr {
	book.mtx.RLock()
	defer book.mtx.RUnlock()

	s := make([]net.Addr, len(book.known))
	for i, e := range book.known {
		s[i] = e.Address
	}

	return s
}

func (book *addressBook) KnownPipes() []*Pipe {
	book.mtx.RLock()
	defer book.mtx.RUnlock()

	s := make([]*Pipe, len(book.known))
	for i, e := range book.known {
		s[i] = e.Pipe
	}

	return s
}

func (book *addressBook) HandshakePipes() []*Pipe {
	book.mtx.RLock()
	defer book.mtx.RUnlock()

	s := make([]*Pipe, 0, len(book.known))
	for _, e := range book.known {
		if !e.IsBackup {
			continue
		}
		s = append(s, e.Pipe)
	}

	return s
}

func (book *addressBook) NextHandshakeEpoch() {
	book.mtx.Lock()
	defer book.mtx.Unlock()

	var (
		now = time.Now()
	)

	if len(book.known) == 0 {
		book.active = nil
		return
	}

	for _, e := range book.known {

		if !e.SendHandshakeAt.IsZero() {
			// sent request
			if !e.ReceivedHandshakeAt.IsZero() {
				// successful handshake: update latency
				e.AddLatencySample(e.ReceivedHandshakeAt.Sub(e.SendHandshakeAt))
				e.ExpireAt = e.ReceivedHandshakeAt.Add(2 * time.Minute)
				e.Reachable = true
				book.log.Printf("\x1B[34mUpdated path\x1B[0m %s (latency=\x1B[33m%s\x1B[0m, emwa=\x1B[33m%s\x1B[0m)", e, e.latency, e.ewma)

			} else {
				// no response
				if e.ExpireAt.Before(now) {
					// reached deadline
					e.Reachable = false
					e.latency = 125 * time.Millisecond
					e.ewma = 125 * time.Millisecond
					book.log.Printf("\x1B[31mDetected broken path\x1B[0m %s", e)

				} else {
					e.AddLatencySample(now.Sub(e.SendHandshakeAt))
					book.log.Printf("\x1B[34mUpdated path\x1B[0m %s (latency=\x1B[33m%s\x1B[0m, emwa=\x1B[33m%s\x1B[0m)", e, e.latency, e.ewma)

				}
			}
		}

		// reset
		e.SendHandshakeAt = time.Time{}
		e.ReceivedHandshakeAt = time.Time{}

	}

	// sort by state and latency
	sort.Sort(sortedAddressBookEntries(book.known))

	// trim
	if len(book.known) > cMaxAddressBookEntries {
		book.known = book.known[:cMaxAddressBookEntries]
	}

	// update active
	var oldActive = book.active
	if book.known[0].Reachable {
		book.active = book.known[0]
	} else {
		book.active = nil
	}
	if book.active != oldActive {
		book.log.Printf("\x1B[32mChanged path\x1B[0m from %s to %s", oldActive, book.active)
	}

	// update fallbacks
	for i, entry := range book.known {
		if entry.Reachable && i < cNumBackupAddresses {
			entry.IsBackup = true
		} else {
			entry.IsBackup = false
		}
	}

}

func (book *addressBook) PipeToAddr(addr net.Addr) *Pipe {
	book.mtx.RLock()
	var (
		idx = book.indexOf(addr)
		e   *addressBookEntry
	)

	if idx >= 0 {
		e = book.known[idx]
	}
	book.mtx.RUnlock()

	if e != nil {
		return e.Pipe
	}
	return nil
}

func (book *addressBook) AddPipe(p *Pipe) {
	book.mtx.Lock()
	defer book.mtx.Unlock()

	var (
		now = time.Now()
		idx = book.indexOfPipe(p)
		e   *addressBookEntry
	)

	if idx >= 0 {
		return
	}

	e = &addressBookEntry{Address: p.raddr, Pipe: p}
	e.Added = now
	e.ExpireAt = now.Add(2 * time.Minute)
	e.Reachable = true
	e.IsBackup = true
	e.InitSamples()

	book.known = append(book.known, e)
	book.log.Printf("\x1B[32mDiscovered path\x1B[0m %s (latency=\x1B[33m%s\x1B[0m, emwa=\x1B[33m%s\x1B[0m)", e, e.latency, e.ewma)

	if book.active == nil {
		book.active = e
		book.log.Printf("\x1B[32mChanged path\x1B[0m from %s to %s", (*addressBookEntry)(nil), book.active)
	}
}

func (book *addressBook) SentHandshake(pipe *Pipe) {
	book.mtx.Lock()
	defer book.mtx.Unlock()

	var (
		idx = book.indexOfPipe(pipe)
	)

	if idx < 0 {
		return
	}

	e := book.known[idx]
	e.SendHandshakeAt = time.Now()
}

func (book *addressBook) ReceivedHandshake(p *Pipe) {
	book.mtx.Lock()
	defer book.mtx.Unlock()

	var (
		idx = book.indexOfPipe(p)
		e   *addressBookEntry
	)

	if idx < 0 {
		book.AddPipe(p)
		return
	}

	e = book.known[idx]
	if !e.SendHandshakeAt.IsZero() {
		e.ReceivedHandshakeAt = time.Now()
	}
}

func (book *addressBook) indexOf(addr net.Addr) int {
	for i, e := range book.known {
		if transports.EqualAddr(e.Address, addr) {
			return i
		}
	}
	return -1
}

func (book *addressBook) indexOfPipe(pipe *Pipe) int {
	for i, e := range book.known {
		if e.Pipe == pipe {
			return i
		}
	}
	return -1
}

func (a *addressBookEntry) String() string {
	if a == nil {
		return "<nil>"
	}
	return a.Address.String()
}

func (a *addressBookEntry) AddLatencySample(d time.Duration) {
	a.latency = d
	a.ewma = time.Duration(ewma_α*float64(d) + (1.0-ewma_α)*float64(a.ewma))
}

func (a *addressBookEntry) InitSamples() {
	a.latency = 125 * time.Millisecond
	a.ewma = 125 * time.Millisecond
}

type sortedAddressBookEntries []*addressBookEntry

func (s sortedAddressBookEntries) Len() int      { return len(s) }
func (s sortedAddressBookEntries) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortedAddressBookEntries) Less(i, j int) bool {
	if s[i].Reachable && !s[j].Reachable {
		return true
	}

	if !s[i].Reachable && s[j].Reachable {
		return false
	}

	return s[i].ewma < s[j].ewma
}

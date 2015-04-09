package kademlia

import (
	"testing"

	mrand "math/rand"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
)

func Test_Seek(t *testing.T) {
	var hashnames = makeRandomHashnames(10000)
	var tab table
	tab.localHashname = selectRandomHashname(hashnames)
	tab.init()

	for i := 0; i < 100; i++ {
		peer := selectRandomHashname(hashnames)
		for peer == tab.localHashname {
			peer = selectRandomHashname(hashnames)
		}

		tab.addCandidate(peer, peer)
	}

	for {
		c := tab.nextCandidate()
		if c == nil {
			break
		}
		tab.activatePeer(c.hashname, mesh.Tag{})
	}

	seek := Seek{
		table:  &tab,
		driver: &randomDriver{hashnames},
	}

	seek.setOptions(NumResults(4))

	out := seek.seek()

	t.Logf("out=%v", &out)
}

type randomDriver struct {
	hashnames []hashname.H
}

func (d *randomDriver) Seek(peer hashname.H, target Key) ([]hashname.H, error) {
	return selectRandomHashnames(d.hashnames, 5), nil
}

func (d *randomDriver) Link(peer hashname.H) error {
	return nil
}

func (d *randomDriver) Unlink(peer hashname.H) {
}

func makeRandomHashnames(n int) []hashname.H {
	l := make([]hashname.H, n)
	for i := 0; i < n; i++ {
		l[i] = makeRandomHashname()
	}
	return l
}

func selectRandomHashname(l []hashname.H) hashname.H {
	return l[mrand.Intn(len(l))]
}

func selectRandomHashnames(l []hashname.H, n int) []hashname.H {
	cache := map[hashname.H]bool{}
	s := make([]hashname.H, 0, n)

	for len(s) < n {
		hn := selectRandomHashname(l)
		if !cache[hn] {
			cache[hn] = true
			s = append(s, hn)
		}
	}

	return s
}

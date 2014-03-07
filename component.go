package telehash

import (
	"sync"
)

type Component interface {
	Start(sw *Switch, wg *sync.WaitGroup) error
	Stop() error
}

type HookNewPeer interface {
	OnNewPeer(peer *Peer)
}

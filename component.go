package telehash

type Component interface {
	Start(sw *Switch) error
	Stop() error
}

type HookNewPeer interface {
	OnNewPeer(peer *Peer)
}

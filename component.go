package telehash

type Component interface {
	Start(sw *Switch) error
	Stop() error
}

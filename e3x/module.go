package e3x

type Module interface {
	Init() error
	Start() error
	Stop() error
}

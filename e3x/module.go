package e3x

// Module must be implemented by endpoint modules.
type Module interface {
	// Init is called after the creating the endpoint and before openeing the endpoint transport.
	Init() error

	// Start is called after opening the endpoint transport.
	Start() error

	// Stop is called before closing the endpoint transport.
	Stop() error
}

type pivateModKey string

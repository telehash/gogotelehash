package fw

import (
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*firewall)(nil)
)

// Config for the fw transport.
type Config struct {
	Config transports.Config // the sub-transport configuration
	Allow  Rule              // the firewall rule.
}

// Rule must be implemented by rule objects.
type Rule interface {
	// Match must return true when p and/or src match the rule.
	Match(p []byte, src transports.Addr) bool
}

type firewall struct {
	t    transports.Transport
	rule Rule
}

// Open opens the sub-transport
func (c Config) Open() (transports.Transport, error) {
	t, err := c.Config.Open()
	if err != nil {
		return nil, err
	}

	return &firewall{t, c.Allow}, nil
}

func (fw *firewall) LocalAddresses() []transports.Addr {
	return fw.t.LocalAddresses()
}

func (fw *firewall) ReadMessage(p []byte) (n int, src transports.Addr, err error) {
	for {
		n, src, err = fw.t.ReadMessage(p)
		if err != nil {
			return n, src, err
		}

		if fw.rule == nil || fw.rule.Match(p[:n], src) {
			return n, src, err
		}

		// continue
	}
}

func (fw *firewall) WriteMessage(p []byte, dst transports.Addr) error {
	return fw.t.WriteMessage(p, dst)
}

func (fw *firewall) Close() error {
	return fw.t.Close()
}

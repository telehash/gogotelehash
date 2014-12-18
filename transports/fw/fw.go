package fw

import (
	"net"

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
	// Match must return true when src match the rule.
	Match(src net.Addr) bool
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

func (fw *firewall) Addrs() []net.Addr {
	return fw.t.Addrs()
}

func (fw *firewall) Dial(addr net.Addr) (net.Conn, error) {
	return fw.t.Dial(addr)
}

func (fw *firewall) Accept() (c net.Conn, err error) {
RETRY:
	conn, err := fw.t.Accept()
	if err != nil {
		return nil, err
	}

	if fw.rule != nil && !fw.rule.Match(conn.RemoteAddr()) {
		conn.Close()
		goto RETRY
	}

	return conn, nil
}

func (fw *firewall) Close() error {
	return fw.t.Close()
}

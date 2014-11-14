// Package unix implements the UNIX domain sockets transport.
package unix

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path"

	"github.com/telehash/gogotelehash/transports"
)

func init() {
	transports.RegisterAddrDecoder("unix", decodeAddress)
}

// Config for the UDP transport. Typically the zero value is sufficient to get started.
//
//   e3x.New(keys, unix.Config{Name: "/tmp/telehash/<hashname>.sock"})
type Config struct {
	// Name of the UNIX domain socket.
	// Name defaults to a random path of format "/tmp/telehash-<random>.sock"
	Name string

	// Mode is the mode for the socket.
	// Deault to srwx------ (user only)
	Mode os.FileMode
}

type addr struct {
	net.UnixAddr
}

type transport struct {
	laddr *net.UnixAddr
	c     *net.UnixConn
}

var (
	_ transports.Addr      = (*addr)(nil)
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

// Open opens the transport.
func (c Config) Open() (transports.Transport, error) {
	if c.Name == "" {
		c.Name = path.Join(os.TempDir(), "telehash-"+randomString(8)+".sock")
	}

	if c.Mode == 0 {
		c.Mode = 0700
	}

	laddr, err := net.ResolveUnixAddr("unixgram", c.Name)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		return nil, err
	}

	err = os.Chmod(laddr.Name, c.Mode)
	if err != nil {
		conn.Close()
		os.Remove(laddr.Name)
		return nil, err
	}

	return &transport{laddr, conn}, nil
}

func (t *transport) ReadMessage(p []byte) (int, transports.Addr, error) {
	n, a, err := t.c.ReadFromUnix(p)
	if err != nil {
		if err.Error() == "use of closed network connection" {
			err = transports.ErrClosed
		}
		return 0, nil, err
	}

	return n, &addr{UnixAddr: *a}, nil
}

func (t *transport) WriteMessage(p []byte, dst transports.Addr) error {
	a, ok := dst.(*addr)
	if !ok || a == nil {
		return transports.ErrInvalidAddr
	}

	n, err := t.c.WriteToUnix(p, &a.UnixAddr)
	if err != nil {
		return err
	}

	if n != len(p) {
		return io.ErrShortWrite
	}

	return nil
}

func (t *transport) LocalAddresses() []transports.Addr {
	return []transports.Addr{&addr{UnixAddr: *t.laddr}}
}

func (t *transport) Close() error {
	err := t.c.Close()

	if t.laddr.Name != "" {
		os.Remove(t.laddr.Name)
	}

	return err
}

func (a *addr) Network() string {
	return "unix"
}

func decodeAddress(data []byte) (transports.Addr, error) {
	var desc struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return nil, transports.ErrInvalidAddr
	}

	if desc.Name == "" {
		return nil, transports.ErrInvalidAddr
	}

	return &addr{net.UnixAddr{Net: "unixgram", Name: desc.Name}}, nil
}

func (a *addr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}{
		Type: a.Network(),
		Name: a.Name,
	}
	return json.Marshal(&desc)
}

func (a *addr) Equal(x transports.Addr) bool {
	b := x.(*addr)

	if a.Name != b.Name {
		return false
	}

	return true
}

func (a *addr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
}

func randomString(n int) string {
	var buf = make([]byte, n/2)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf)
}

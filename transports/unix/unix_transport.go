// Package unix implements the UNIX domain sockets transport.
package unix

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/transports"
)

func init() {
	transports.RegisterAddr(&unixAddr{})
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

type unixAddr net.UnixAddr

type transport struct {
	laddr    *unixAddr
	listener *net.UnixListener
}

type connection struct {
	transport *transport
	raddr     *unixAddr
	conn      *net.UnixConn
	bufr      *bufio.Reader
	mtxWrite  sync.Mutex
	mtxRead   sync.Mutex
}

var (
	_ net.Addr             = (*unixAddr)(nil)
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
	c.Mode &= os.ModePerm
	c.Mode |= os.ModeSocket

	laddr, err := net.ResolveUnixAddr("unix", c.Name)
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return nil, err
	}

	err = os.Chmod(laddr.Name, c.Mode)
	if err != nil {
		listener.Close()
		os.Remove(laddr.Name)
		return nil, err
	}

	return &transport{(*unixAddr)(laddr), listener}, nil
}

// func (t *transport) ReadMessage(p []byte) (int, net.Addr, error) {
// 	n, a, err := t.c.ReadFromUnix(p)
// 	if err != nil {
// 		if err.Error() == "use of closed network connection" {
// 			err = transports.ErrClosed
// 		}
// 		return 0, nil, err
// 	}

// 	return n, &addr{UnixAddr: *a}, nil
// }

// func (t *transport) WriteMessage(p []byte, dst net.Addr) error {
// 	a, ok := dst.(*addr)
// 	if !ok || a == nil {
// 		return transports.ErrInvalidAddr
// 	}

// 	n, err := t.c.WriteToUnix(p, &a.UnixAddr)
// 	if err != nil {
// 		return err
// 	}

// 	if n != len(p) {
// 		return io.ErrShortWrite
// 	}

// 	return nil
// }

func (t *transport) Addrs() []net.Addr {
	return []net.Addr{t.laddr}
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	switch x := addr.(type) {
	case *unixAddr:
		conn, err := net.DialUnix("unix", nil, (*net.UnixAddr)(x))
		if err != nil {
			return nil, err
		}

		return &connection{transport: t, raddr: x, conn: conn, bufr: bufio.NewReader(conn)}, nil
	case *net.UnixAddr:
		return t.Dial((*unixAddr)(x))
	default:
		return nil, transports.ErrInvalidAddr
	}
}

func (t *transport) Accept() (c net.Conn, err error) {
	uconn, err := t.listener.AcceptUnix()
	if err != nil {
		return nil, err
	}

	raddr := uconn.RemoteAddr().(*net.UnixAddr)

	conn := &connection{transport: t, raddr: (*unixAddr)(raddr), conn: uconn, bufr: bufio.NewReader(uconn)}
	return conn, nil
}

func (t *transport) Close() error {
	err := t.listener.Close()

	if t.laddr.Name != "" {
		os.Remove(t.laddr.Name)
	}

	return err
}

func (c *connection) Read(b []byte) (n int, err error) {
	var hdr [2]byte

	c.mtxRead.Lock()
	defer c.mtxRead.Unlock()

	_, err = io.ReadFull(c.bufr, hdr[:])
	if err != nil {
		return 0, err
	}

	msgLen := binary.BigEndian.Uint16(hdr[:])

	return io.ReadFull(c.bufr, b[:msgLen])
}

func (c *connection) Write(b []byte) (n int, err error) {
	var lenB = len(b)
	if lenB > 1472 {
		return 0, io.ErrShortWrite
	}

	var hdr [2]byte
	var hdrP = hdr[:]
	binary.BigEndian.PutUint16(hdrP, uint16(lenB))

	c.mtxWrite.Lock()
	defer c.mtxWrite.Unlock()

	for len(hdrP) > 0 {
		n, err := c.conn.Write(hdrP)
		if err != nil {
			return 0, err
		}
		hdrP = hdrP[n:]
	}

	for len(b) > 0 {
		n, err := c.conn.Write(b)
		if err != nil {
			return 0, err
		}
		b = b[n:]
	}

	return lenB, nil
}

func (c *connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *connection) LocalAddr() net.Addr {
	return c.transport.laddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) Close() error {
	return c.conn.Close()
}

func (a *unixAddr) Network() string {
	return "unix"
}

func (a *unixAddr) String() string {
	return (*net.UnixAddr)(a).String()
}

func (a *unixAddr) UnmarshalJSON(data []byte) error {
	var desc struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return transports.ErrInvalidAddr
	}

	if desc.Name == "" {
		return transports.ErrInvalidAddr
	}

	*a = unixAddr{Net: "unixgram", Name: desc.Name}
	return nil
}

func (a *unixAddr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}{
		Type: a.Network(),
		Name: a.Name,
	}
	return json.Marshal(&desc)
}

func randomString(n int) string {
	var buf = make([]byte, n/2)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(buf)
}

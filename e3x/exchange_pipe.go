package e3x

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/util/bufpool"
)

// Connection life-cycle
//
//   New connections are added to the testing group as we don't know their quality.
//
//   Connections in the testing group will be send all handshake packets.
//   All packets read from the testing group are be accepted.
//   When a connection in the test group successfully completes a handshake roundtrip
//   (initiated by the local peer) the connection is promoted to the active group.
//   When a connection fails to complete a handshake roundtrip it is closed.
//
//   Connections in the active group will be send all handshake packets.
//   All packets read from the active group are be accepted.
//   The connections are also prioritized based on there remote addr/transport type
//   The connection with the highest priority will be send all packets and is
//   considered the active connection.
//   When a connection fails to complete a handshake roundtrip it is demoted to the
//   testing group.
//
//   A handshake roundtrip is initiated by the local peer and must not take longer than
//   1 minute.
//

type pipe struct {
	mtx         sync.Mutex
	wg          sync.WaitGroup
	connections []net.Conn
	cRead       chan readOp
}

type readOp struct {
	msg  []byte
	conn net.Conn
}

func (p *pipe) AddConnection(conn net.Conn) (ok bool) {
	if conn == nil || p == nil {
		return false
	}

	p.mtx.Lock()
	found := false
	for _, other := range p.connections {
		if other == conn {
			found = true
			break
		}
	}
	if found {
		p.mtx.Unlock()
		return false
	}
	p.connections = append(p.connections, conn)
	p.mtx.Unlock()

	p.wg.Add(1)
	go p.reader(conn)

	return true
}

func (p *pipe) removeConnection(conn net.Conn) {
	if conn == nil || p == nil {
		return
	}

	// ensure conn is closed
	conn.Close()

	p.mtx.Lock()
	for idx, other := range p.connections {
		if other == conn {
			copy(p.connections[idx:], p.connections[idx+1:])
			p.connections = p.connections[:len(p.connections)-1]
			break
		}
	}
	p.mtx.Unlock()
}

func (p *pipe) reader(conn net.Conn) {
	defer p.wg.Done()
	defer p.removeConnection(conn)

	var (
		b []byte
	)

	for {
		if b == nil {
			b = bufpool.GetBuffer()
		}

		n, err := conn.Read(b)

		if err == nil {
			p.cRead <- readOp{b[:n], conn}
			b = nil
			continue
		}

		if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		if err != nil {
			return
		}
	}
}

func (p *pipe) Read(b []byte) (n int, conn net.Conn, err error) {
	op, ok := <-p.cRead
	if !ok {
		return 0, nil, io.EOF
	}

	copy(b, op.msg)
	return len(op.msg), op.conn, nil
}

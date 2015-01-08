package chord

import (
	"bufio"
	"io"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/internal/lob"
)

type stream struct {
	ch *e3x.Channel
	r  *bufio.Reader
}

type streamReader struct {
	ch *e3x.Channel
}

func newStream(ch *e3x.Channel) io.ReadWriteCloser {
	return &stream{ch, bufio.NewReaderSize(&streamReader{ch}, 16*1024)}
}

func (s *stream) Write(p []byte) (int, error) {
	var n int

	for len(p) > 0 {
		var chunk = p
		if len(chunk) > 1000 {
			chunk = chunk[:1000]
			p = p[1000:]
		} else {
			p = nil
		}

		pkt := &lob.Packet{Body: chunk}
		err := s.ch.WritePacket(pkt)
		if err != nil {
			return n, err
		}

		n += len(chunk)
	}

	return n, nil
}

func (s *stream) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *stream) Close() error {
	return s.ch.Close()
}

func (s *streamReader) Read(p []byte) (int, error) {
	pkt, err := s.ch.ReadPacket()
	if err != nil {
		return 0, err
	}

	copy(p, pkt.Body)
	return len(pkt.Body), nil
}

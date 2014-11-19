package thtp

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/lob"
)

var (
	_ http.ResponseWriter = (*responseWriter)(nil)
	_ http.Flusher        = (*responseWriter)(nil)
	_ e3x.Module          = (*module)(nil)
)

func Server(handler http.Handler) func(*e3x.Endpoint) error {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, &module{
			endpoint: e,
			handler:  handler,
			log:      log.New(os.Stderr, "", 0),
		})(e)
	}
}

type moduleKeyType string

const moduleKey = moduleKeyType("thtp")

type module struct {
	endpoint *e3x.Endpoint
	listener *e3x.Listener
	handler  http.Handler
	log      *log.Logger
}

func (mod *module) Init() error {
	mod.listener = mod.endpoint.Listen("thtp", true)
	return nil
}

func (mod *module) Start() error {
	go mod.run()
	return nil
}

func (mod *module) Stop() error {
	if mod.listener != nil {
		mod.listener.Close()
	}
	return nil
}

func (mod *module) run() {
	for {
		c, err := mod.listener.AcceptChannel()
		if err == io.EOF {
			return
		}
		if err != nil {
			mod.logf("failed to accept: %s", err)
			continue
		}
		go mod.serveTelehash(c)
	}
}

func (mod *module) logf(format string, args ...interface{}) {
	if mod.log != nil {
		mod.log.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (mod *module) serveTelehash(c *e3x.Channel) {
	defer c.Close()

	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			mod.logf("thtp: panic serving %s: %v\n%s", c.RemoteHashname(), err, buf)
		}
	}()

	req, err := mod.readRequest(c)
	if err != nil {
		return
	}

	rw := newResponseWriter(c)
	defer rw.Flush()

	mod.handler.ServeHTTP(rw, req)
}

func (mod *module) readRequest(c *e3x.Channel) (*http.Request, error) {
	var (
		r   = bufio.NewReaderSize(&serverPacketReader{c: c}, 64*1024)
		req *http.Request
		err error
	)

	{ // read the header
		var (
			headLenData [2]byte
			headLen     uint16
			headerData  []byte
			header      map[string]string
		)

		_, err = io.ReadFull(r, headLenData[:])
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}

		headLen = binary.BigEndian.Uint16(headLenData[:])
		headerData = make([]byte, headLen)
		_, err = io.ReadFull(r, headerData)
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}

		err = json.Unmarshal(headerData, &header)
		if err != nil {
			return nil, err
		}

		req = &http.Request{}
		req.Method = strings.ToUpper(header[":method"])
		req.URL, err = url.ParseRequestURI(header[":path"])
		if err != nil {
			return nil, err
		}
		req.Header = make(http.Header, len(header))
		req.Proto = "1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		for k, v := range header {
			if k != "method" && k != "path" {
				req.Header.Set(http.CanonicalHeaderKey(k), v)
			}
		}
	}

	{ // set the body
		req.Body = ioutil.NopCloser(r)
	}

	return req, nil
}

type serverPacketReader struct {
	c              *e3x.Channel
	send_handshake bool
}

func (r *serverPacketReader) Read(p []byte) (int, error) {
	pkt, err := r.c.ReadPacket()
	if err != nil {
		return 0, err
	}

	if len(p) < len(pkt.Body) {
		return 0, io.ErrShortBuffer
	}

	if !r.send_handshake {
		err := r.c.WritePacket(&lob.Packet{})
		if err != nil {
			return 0, err
		}

		r.send_handshake = true
	}

	copy(p, pkt.Body)
	return len(pkt.Body), nil
}

type responseWriter struct {
	header http.Header
	code   int
	buf    *bufio.Writer
}

func newResponseWriter(c *e3x.Channel) *responseWriter {
	return &responseWriter{
		header: make(http.Header),
		buf:    bufio.NewWriterSize(&serverPacketWriter{c}, 1200),
	}
}

func (rw *responseWriter) Header() http.Header {
	return rw.header
}

func (rw *responseWriter) Flush() {
	rw.buf.Flush()
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if rw.code == 0 {
		rw.WriteHeader(200)
	}

	return rw.buf.Write(p)
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.code != 0 {
		return
	}

	var (
		header     = make(map[string]interface{}, len(rw.header)+1)
		headerData []byte
		headerLen  [2]byte
		err        error
	)

	for k, v := range rw.header {
		if len(v) == 0 {
			continue
		}

		e := v[0]
		if e == "" {
			continue
		}

		header[k] = e
	}

	header[":status"] = code
	rw.code = code

	headerData, err = json.Marshal(header)
	if err != nil {
		return
	}

	binary.BigEndian.PutUint16(headerLen[:], uint16(len(headerData)))

	_, err = rw.buf.Write(headerLen[:])
	if err != nil {
		return
	}

	_, err = rw.buf.Write(headerData)
	if err != nil {
		return
	}
}

type serverPacketWriter struct {
	c *e3x.Channel
}

func (w *serverPacketWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > 1200 {
		n = 1200
		p = p[:1200]
	}

	err := w.c.WritePacket(&lob.Packet{Body: p})
	if err != nil {
		return 0, err
	}

	return n, nil
}

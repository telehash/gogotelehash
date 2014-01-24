package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/fd/go-socket.io"
	"github.com/telehash/gogotelehash"
	th "github.com/telehash/gogotelehash/net"
	"net"
	"net/http"
)

const network = "http"

type Transport struct {
	PublicURL  string
	ListenAddr string
	Config     socketio.Config
	sio        *socketio.SocketIOServer
	listener   net.Listener
	sessions   map[string]*socketio.Session
	rcv        chan pkt_t
}

type pkt_t struct {
	data []byte
	addr th.Addr
}

type event_t struct {
	Data string `json:"data"`
}

func (t *Transport) Network() string {
	return network
}

func (t *Transport) Start(sw *telehash.Switch) error {

	if t.Config.HeartbeatTimeout == 0 {
		t.Config.HeartbeatTimeout = 2
	}

	if t.Config.ClosingTimeout == 0 {
		t.Config.ClosingTimeout = 4
	}

	t.sessions = make(map[string]*socketio.Session)

	t.sio = socketio.NewSocketIOServer(&t.Config)
	if err := t.sio.On("connect", t.on_connect); err != nil {
		return err
	}
	if err := t.sio.On("disconnect", t.on_disconnect); err != nil {
		return err
	}
	if err := t.sio.On("packet", t.on_packet); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", t.ListenAddr)
	if err != nil {
		return err
	}
	t.listener = listener
	t.rcv = make(chan pkt_t)

	go func() {
		defer func() { close(t.rcv) }()
		http.Serve(t.listener, t.sio)
	}()

	return nil
}

func (t *Transport) Stop() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

func (t *Transport) LocalAddresses() []th.Addr {
	return []th.Addr{&Addr{URL: t.PublicURL}}
}

func (t *Transport) ReadFrom(b []byte) (int, th.Addr, error) {
	pkt, opened := <-t.rcv
	if !opened {
		return 0, nil, th.ErrTransportClosed
	}

	copy(b, pkt.data)
	return len(pkt.data), pkt.addr, nil
}

func (t *Transport) WriteTo(b []byte, addr th.Addr) (int, error) {
	var (
		session *socketio.Session
		event   event_t
	)

	if a, ok := addr.(*internal_addr); ok {
		session = t.sessions[a.SessionID]
	}
	if session == nil {
		return 0, errors.New("unreachable session")
	}

	event.Data = base64.StdEncoding.EncodeToString(b)
	err := session.Of("").Emit("packet", &event)
	if err == socketio.NotConnected {
		return 0, th.ErrTransportClosed
	}
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func _net_conn_is_closed_err(err error) bool {
	if err == nil {
		return false
	}

	const s = "use of closed network connection"

	switch v := err.(type) {
	case *net.OpError:
		return _net_conn_is_closed_err(v.Err)
	default:
		return s == v.Error()
	}
}

func (t *Transport) on_connect(ns *socketio.NameSpace) {
	t.sessions[ns.Session.SessionId] = ns.Session
}

func (t *Transport) on_disconnect(ns *socketio.NameSpace) {
	t.sessions[ns.Session.SessionId] = ns.Session
}

func (t *Transport) on_packet(ns *socketio.NameSpace, e event_t) {
	data, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		return
	}

	t.rcv <- pkt_t{data, &internal_addr{ns.Session.SessionId}}
}

func init() {
	th.RegisterPathEncoder("http", func(n th.Addr) ([]byte, error) {
		a := n.(*Addr)

		var (
			j = struct {
				Http string `json:"http"`
			}{
				Http: a.URL,
			}
		)

		return json.Marshal(j)
	})

	th.RegisterPathDecoder("http", func(data []byte) (th.Addr, error) {
		var (
			j struct {
				Http string `json:"http"`
			}
		)

		err := json.Unmarshal(data, &j)
		if err != nil {
			return nil, err
		}

		if j.Http == "" {
			return nil, ErrInvalidHTTPAddress
		}

		return &Addr{URL: j.Http}, nil
	})
}

package e3x

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/mux"
	"github.com/telehash/gogotelehash/transports/udp"
	"github.com/telehash/gogotelehash/util/logs"
	"github.com/telehash/gogotelehash/util/tracer"
)

type endpointState uint8

const (
	endpointStateUnknown endpointState = iota
	endpointStateRunning
	endpointStateTerminated
	endpointStateBroken
)

// Endpoint represents a Telehash endpoint.
type Endpoint struct {
	TID tracer.ID // tracer id

	mtx   sync.Mutex
	state endpointState
	err   error

	hashname        hashname.H
	keys            cipherset.Keys
	log             *logs.Logger
	transportConfig transports.Config
	transport       transports.Transport
	modules         map[interface{}]Module

	tokens    map[cipherset.Token]*Exchange
	hashnames map[hashname.H]*Exchange
	listeners map[string]*Listener
}

type EndpointOption func(e *Endpoint) error

func Open(options ...EndpointOption) (*Endpoint, error) {
	e := &Endpoint{
		TID:       tracer.NewID(),
		listeners: make(map[string]*Listener),
		modules:   make(map[interface{}]Module),
		tokens:    make(map[cipherset.Token]*Exchange),
		hashnames: make(map[hashname.H]*Exchange),
	}

	observers := &modObservers{}
	observers.Register(e.onExchangeClosed)

	err := e.setOptions(
		RegisterModule(modObserversKey, observers),
		RegisterModule(modForgetterKey, &modForgetter{e}),
		RegisterModule(modTransportsKey, &modTransports{e}))
	if err != nil {
		return nil, e.traceError(err)
	}

	err = e.setOptions(options...)
	if err != nil {
		return nil, e.traceError(err)
	}

	err = e.setOptions(
		defaultRandomKeys,
		defaultTransport)
	if err != nil {
		return nil, e.traceError(err)
	}

	e.traceNew()

	err = e.start()
	if err != nil {
		e.close()
		return nil, e.traceError(err)
	}

	e.traceStarted()
	return e, nil
}

func (e *Endpoint) getTID() tracer.ID {
	return e.TID
}

func (e *Endpoint) getTransport() transports.Transport {
	return e.transport
}

func (e *Endpoint) traceError(err error) error {
	if tracer.Enabled && err != nil {
		tracer.Emit("endpoint.error", tracer.Info{
			"endpoint_id": e.TID,
			"error":       err.Error(),
		})
	}
	return err
}

func (e *Endpoint) traceNew() {
	if tracer.Enabled {
		tracer.Emit("endpoint.new", tracer.Info{
			"endpoint_id": e.TID,
			"hashname":    e.hashname.String(),
		})
	}
}

func (e *Endpoint) traceStarted() {
	if tracer.Enabled {
		tracer.Emit("endpoint.started", tracer.Info{
			"endpoint_id": e.TID,
		})
	}
}

func (e *Endpoint) traceReceivedPacket(msg message) {
	if tracer.Enabled {
		pkt := tracer.Info{
			"msg": base64.StdEncoding.EncodeToString(msg.Data),
		}

		if msg.Pipe != nil {
			pkt["src"] = msg.Pipe.raddr.String()
		}

		tracer.Emit("endpoint.rcv.packet", tracer.Info{
			"endpoint_id": e.TID,
			"packet_id":   msg.TID,
			"packet":      pkt,
		})
	}
}

func (e *Endpoint) traceDroppedPacket(msg []byte, conn net.Conn, reason string) {
	if tracer.Enabled {
		pkt := tracer.Info{
			"msg": base64.StdEncoding.EncodeToString(msg),
		}

		if conn != nil {
			pkt["src"] = conn.RemoteAddr()
			pkt["dst"] = conn.LocalAddr()
		}

		tracer.Emit("endpoint.drop.packet", tracer.Info{
			"endpoint_id": e.TID,
			"packet_id":   tracer.NewID(),
			"reason":      reason,
			"packet":      pkt,
		})
	}
}

func (e *Endpoint) setOptions(options ...EndpointOption) error {
	for _, option := range options {
		if err := option(e); err != nil {
			return err
		}
	}
	return nil
}

func RegisterModule(key interface{}, mod Module) EndpointOption {
	return func(e *Endpoint) error {
		e.mtx.Lock()
		defer e.mtx.Unlock()

		if e.state != endpointStateUnknown {
			panic("(*Endpoint).Use() can only be called when Endpoint is not yet started.")
		}

		if _, found := e.modules[key]; found {
			panic("This module is already registered.")
		}

		e.modules[key] = mod
		return nil
	}
}

func Keys(keys cipherset.Keys) EndpointOption {
	return func(e *Endpoint) error {
		if e.keys != nil && len(e.keys) > 0 {
			return nil
		}

		hn, err := hashname.FromKeys(keys)
		if err != nil {
			return err
		}

		e.keys = keys
		e.hashname = hn

		if e.log != nil {
			e.log = e.log.From(e.hashname)
		}

		return nil
	}
}

func defaultRandomKeys(e *Endpoint) error {
	if e.keys != nil && len(e.keys) > 0 {
		return nil
	}

	keys, err := cipherset.GenerateKeys()
	if err != nil {
		return err
	}

	return Keys(keys)(e)
}

func Log(w io.Writer) EndpointOption {
	if w == nil {
		w = os.Stderr
	}

	return func(e *Endpoint) error {
		e.log = logs.New(w).Module("e3x")
		if e.hashname != "" {
			e.log = e.log.From(e.hashname)
		}
		return nil
	}
}

func DisableLog() EndpointOption {
	return func(e *Endpoint) error {
		e.log = nil
		return nil
	}
}

func Transport(config transports.Config) EndpointOption {
	return func(e *Endpoint) error {
		if e.transportConfig != nil {
			return fmt.Errorf("endpoint already has a transport")
		}

		e.transportConfig = config
		return nil
	}
}

func defaultTransport(e *Endpoint) error {
	if e.transportConfig != nil {
		return nil
	}

	return Transport(&mux.Config{
		udp.Config{Network: "udp4"},
		udp.Config{Network: "udp6"},
	})(e)
}

// Listen makes a new channel listener.
func (e *Endpoint) Listen(typ string, reliable bool) *Listener {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if _, f := e.listeners[typ]; f {
		panic("listener is already registered: " + typ)
	}

	l := newListener(e, typ, reliable, 0)
	e.listeners[typ] = l
	return l
}

func (e *Endpoint) listener(channelType string) *Listener {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	return e.listeners[channelType]
}

func (e *Endpoint) unregisterListener(channelType string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	delete(e.listeners, channelType)
}

func (e *Endpoint) LocalHashname() hashname.H {
	return e.hashname
}

func (e *Endpoint) LocalIdentity() (*Identity, error) {
	return NewIdentity(e.keys, nil, e.transport.Addrs())
}

func (e *Endpoint) start() error {
	if e.state == endpointStateBroken {
		return e.err
	}

	if e.state != endpointStateUnknown {
		panic("e3x: Endpoint cannot be started more than once")
	}

	for _, mod := range e.modules {
		err := mod.Init()
		if err != nil {
			e.err = err
			return err
		}
	}

	t, err := e.transportConfig.Open()
	if err != nil {
		e.err = err
		return err
	}
	e.transport = t
	go e.acceptConnections()

	for _, mod := range e.modules {
		err := mod.Start()
		if err != nil {
			e.err = err
			return err
		}
	}

	return nil
}

func (e *Endpoint) Close() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	return e.close()
}

func (e *Endpoint) close() error {
	e.mtx.Unlock()
	for _, mod := range e.modules {
		err := mod.Stop()
		if err != nil {
			e.mtx.Lock()
			e.err = err
			return err
		}
	}
	e.mtx.Lock()

	for _, x := range e.hashnames {
		x.onBreak()
	}
	for _, x := range e.tokens {
		x.onBreak()
	}

	e.transport.Close() //TODO handle err

	if e.state == endpointStateRunning {
		e.state = endpointStateTerminated
	} else {
		e.state = endpointStateBroken
	}

	return e.err
}

func (e *Endpoint) acceptConnections() {
	for {
		conn, err := e.transport.Accept()
		if err == io.EOF {
			return
		}
		if err != nil {
			panic(err)
		}

		e.accept(conn)
	}
}

func (e *Endpoint) accept(conn net.Conn) {
	var (
		token cipherset.Token
		buf   [1500]byte
		msg   []byte
		err   error
		n     int
	)
	n, err = conn.Read(buf[:])
	if err != nil {
		return
	}
	msg = buf[:n]

	// msg is either a handshake or a channel packet
	// when msg is a handshake decrypt it and pass it to the associated exchange
	// when msg is a channel packet lookup the exchange and pass it the msg
	// always associate the conn with the exchange

	if len(msg) < 2 {
		return // to short
	}

	token = cipherset.ExtractToken(msg)
	e.mtx.Lock()
	exchange := e.tokens[token]
	e.mtx.Unlock()

	if exchange != nil {
		exchange.received(newMessage(msg, newPipe(e.transport, conn, nil, exchange)))
		return
	}

	if len(msg) < 3 || msg[0] != 0 || msg[1] != 1 {
		return // to short
	}

	localIdent, err := e.LocalIdentity()
	if err != nil {
		e.traceDroppedPacket(msg, conn, err.Error())
		return // drop
	}

	// handle handshakes
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var (
		csid = msg[2]
		key  = e.keys[csid]
	)
	if key == nil {
		return // no key for csid
	}

	handshake, err := cipherset.DecryptHandshake(csid, key, msg[3:])
	if err != nil {
		e.traceDroppedPacket(msg, conn, err.Error())
		return // drop
	}

	hn, err := hashname.FromKeyAndIntermediates(csid,
		handshake.PublicKey().Public(), handshake.Parts())
	if err != nil {
		e.traceDroppedPacket(msg, conn, err.Error())
		return // drop
	}

	exchange = e.hashnames[hn]
	if exchange != nil {
		oldLocalToken := exchange.LocalToken()
		oldRemoteToken := exchange.RemoteToken()
		exchange.received(newMessage(msg, newPipe(e.transport, conn, nil, exchange)))
		newLocalToken := exchange.LocalToken()
		newRemoteToken := exchange.RemoteToken()

		if oldLocalToken != newLocalToken {
			delete(e.tokens, oldLocalToken)
			e.tokens[newLocalToken] = exchange
		}

		if oldRemoteToken != newRemoteToken {
			delete(e.tokens, oldRemoteToken)
			e.tokens[newRemoteToken] = exchange
		}

		return
	}

	exchange, err = newExchange(localIdent, nil, handshake, e, ObserversFromEndpoint(e), e.log)
	if err != nil {
		e.traceDroppedPacket(msg, conn, err.Error())
		return // drop
	}

	e.hashnames[hn] = exchange
	e.tokens[exchange.LocalToken()] = exchange
	e.tokens[exchange.RemoteToken()] = exchange
	exchange.state = ExchangeDialing
	exchange.received(newMessage(msg, newPipe(e.transport, conn, nil, exchange)))
}

func (e *Endpoint) onExchangeClosed(event *ExchangeClosedEvent) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	x := e.hashnames[event.Exchange.remoteIdent.Hashname()]
	if x != nil {
		delete(e.hashnames, x.remoteIdent.Hashname())
		delete(e.tokens, x.LocalToken())
		delete(e.tokens, x.RemoteToken())
	}

}

// func (e *Endpoint) received(op opRead) {
// 	e.traceReceivedPacket(op)

// 	if len(op.msg) >= 3 && op.msg[0] == 0 && op.msg[1] == 1 {
// 		e.mtx.Lock()
// 		defer e.mtx.Unlock()

// 		e.receivedHandshake(op)
// 		return
// 	}

// 	if len(op.msg) >= 2 && op.msg[0] == 0 && op.msg[1] == 0 {
// 		e.receivedPacket(op)
// 		return
// 	}

// 	// drop
// 	const dropReason = "invalid lob packet"
// 	e.traceDroppedPacket(op, dropReason)
// }

// func (e *Endpoint) receivedHandshake(op opRead) {
// 	const (
// 		dropInvalidPacket   = "invalid lob packet"
// 		dropUnsupportedCSID = "unsupported CSID"
// 	)

// 	var (
// 		x          *Exchange
// 		localIdent *Identity
// 		csid       uint8
// 		localKey   cipherset.Key
// 		handshake  cipherset.Handshake
// 		token      cipherset.Token
// 		hn         hashname.H
// 		err        error
// 	)

// 	token = cipherset.ExtractToken(op.msg)
// 	if token == cipherset.ZeroToken {
// 		e.traceDroppedPacket(op, dropInvalidPacket)
// 		return // drop
// 	}

// 	localIdent, err = e.LocalIdentity()
// 	if err != nil {
// 		e.traceDroppedPacket(op, err.Error())
// 		return // drop
// 	}

// 	csid = uint8(op.msg[2])
// 	localKey = localIdent.keys[csid]
// 	if localKey == nil {
// 		e.traceDroppedPacket(op, dropUnsupportedCSID)
// 		return // drop
// 	}

// 	handshake, err = cipherset.DecryptHandshake(csid, localKey, op.msg[3:])
// 	if err != nil {
// 		e.traceDroppedPacket(op, err.Error())
// 		return // drop
// 	}

// 	hn, err = hashname.FromKeyAndIntermediates(csid,
// 		handshake.PublicKey().Public(), handshake.Parts())
// 	if err != nil {
// 		e.traceDroppedPacket(op, err.Error())
// 		return // drop
// 	}

// 	x = e.hashnames[hn]
// 	if x != nil {
// 		oldLocalToken := x.LocalToken()
// 		oldRemoteToken := x.RemoteToken()
// 		x.received(op)
// 		newLocalToken := x.LocalToken()
// 		newRemoteToken := x.RemoteToken()

// 		if oldLocalToken != newLocalToken {
// 			delete(e.tokens, oldLocalToken)
// 			e.tokens[newLocalToken] = x
// 		}

// 		if oldRemoteToken != newRemoteToken {
// 			delete(e.tokens, oldRemoteToken)
// 			e.tokens[newRemoteToken] = x
// 		}

// 		return
// 	}

// 	x, err = newExchange(localIdent, nil, handshake, e, ObserversFromEndpoint(e), e.log)
// 	if err != nil {
// 		e.traceDroppedPacket(op, err.Error())
// 		return // drop
// 	}

// 	e.hashnames[hn] = x
// 	e.tokens[x.LocalToken()] = x
// 	e.tokens[x.RemoteToken()] = x
// 	x.state = ExchangeDialing
// 	x.received(op)
// }

// func (e *Endpoint) receivedPacket(op opRead) {
// 	const (
// 		dropInvalidPacket   = "invalid lob packet"
// 		dropUnknownExchange = "unknown exchange"
// 	)

// 	var (
// 		token = cipherset.ExtractToken(op.msg)
// 	)

// 	if token == cipherset.ZeroToken {
// 		e.traceDroppedPacket(op, dropInvalidPacket)
// 		return // drop
// 	}

// 	e.mtx.Lock()
// 	x := e.tokens[token]
// 	e.mtx.Unlock()
// 	if x == nil {
// 		e.traceDroppedPacket(op, dropUnknownExchange)
// 		return // drop
// 	}

// 	x.received(op)
// }

func (e *Endpoint) Identify(i Identifier) (*Identity, error) {
	return i.Identify(e)
}

// Dial will lookup the identity of identifier, get the exchange for the identity
// and dial the exchange.
func (e *Endpoint) Dial(identifier Identifier) (*Exchange, error) {
	if identifier == nil || e == nil {
		return nil, os.ErrInvalid
	}

	var (
		identity *Identity
		x        *Exchange
		err      error
	)

	identity, err = e.Identify(identifier)
	if err != nil {
		return nil, err
	}

	x, err = e.GetExchange(identity)
	if err != nil {
		return nil, err
	}

	err = x.Dial()
	if err != nil {
		return nil, err
	}

	return x, nil
}

// GetExchange returns the exchange for identity. If the exchange already exists
// it is simply returned otherwise a new exchange is created and registered.
// Not that this GetExchange does not Dial.
func (e *Endpoint) GetExchange(identity *Identity) (*Exchange, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	// Check for existing exchange
	if x, found := e.hashnames[identity.hashname]; found && x != nil {
		return x, nil
	}

	var (
		localIdent *Identity
		x          *Exchange

		err error
	)

	// Get local identity
	localIdent, err = e.LocalIdentity()
	if err != nil {
		return nil, err
	}

	// Make a new exchange struct
	x, err = newExchange(localIdent, identity, nil, e, ObserversFromEndpoint(e), e.log)
	if err != nil {
		return nil, err
	}

	// register the new exchange
	e.tokens[x.LocalToken()] = x
	e.hashnames[identity.hashname] = x

	return x, nil
}

func (e *Endpoint) Module(key interface{}) Module {
	return e.modules[key]
}

func (e *Endpoint) Log() *logs.Logger {
	return e.log
}

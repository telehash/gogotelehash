package e3x

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/mock"

	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/util/tracer"
)

type MockExchange struct {
	mock.Mock
}

func (m *MockExchange) getTID() tracer.ID {
	return tracer.ID(0)
}

func (m *MockExchange) deliverPacket(pkt *lob.Packet, dst *Pipe) error {
	pkt.TID = 0
	args := m.Called(pkt)
	return args.Error(0)
}

func (m *MockExchange) unregisterChannel(channelID uint32) {
	m.Called(channelID)
}

func (m *MockExchange) RemoteIdentity() *Identity {
	args := m.Called()
	return args.Get(0).(*Identity)
}

func dumpExpVar(tb testing.TB) {
	tb.Logf("stat: %s", statsMap)
	resetStats()
}

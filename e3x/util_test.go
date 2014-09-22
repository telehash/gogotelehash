package e3x

import (
	"github.com/stretchr/testify/mock"

	"bitbucket.org/simonmenke/go-telehash/lob"
)

type MockExchange struct {
	mock.Mock
}

func (m *MockExchange) deliver_packet(pkt *lob.Packet) error {
	args := m.Called(pkt)
	return args.Error(0)
}

func (m *MockExchange) unregister_channel(channelId uint32) {
	m.Called(channelId)
}

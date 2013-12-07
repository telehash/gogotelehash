package telehash

import (
	"fmt"
)

type SwitchStats struct {
	KnownPeers int

	// net
	NumSendPackets          uint64
	NumSendPacketErrors     uint64
	NumReceivedPackets      uint64
	NumReceivedPacketErrors uint64

	// lines
	NumRunningLines int
	NumOpenLines    int

	// relay
	RelayNumSendPackets          uint64
	RelayNumSendPacketErrors     uint64
	RelayNumRelayedPackets       uint64
	RelayNumRelayedPacketErrors  uint64
	RelayNumReceivedPackets      uint64
	RelayNumReceivedPacketErrors uint64
}

func (s *Switch) Stats() SwitchStats {
	var (
		stats SwitchStats
	)

	s.net.PopulateStats(&stats)
	s.main.PopulateStats(&stats)
	s.relay_handler.PopulateStats(&stats)

	return stats
}

func (s SwitchStats) String() string {
	return fmt.Sprintf(
		"(peers: known=%d) (net: snd=%d/%d rcv=%d/%d) (lines: running=%d open=%d) (relay: snd=%d/%d rcv=%d/%d relay=%d/%d)",
		s.KnownPeers,
		s.NumSendPackets,
		s.NumSendPacketErrors,
		s.NumReceivedPackets,
		s.NumReceivedPacketErrors,
		s.NumRunningLines,
		s.NumOpenLines,
		s.RelayNumSendPackets,
		s.RelayNumSendPacketErrors,
		s.RelayNumRelayedPackets,
		s.RelayNumRelayedPacketErrors,
		s.RelayNumReceivedPackets,
		s.RelayNumReceivedPacketErrors,
	)
}

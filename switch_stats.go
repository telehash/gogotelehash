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
}

func (s *Switch) Stats() SwitchStats {
	var (
		stats SwitchStats
	)

	s.net.PopulateStats(&stats)
	s.main.PopulateStats(&stats)

	return stats
}

func (s SwitchStats) String() string {
	return fmt.Sprintf(
		"(peers: known=%d) (net: snd=%d snd-err=%d rcv=%d rcv-err=%d) (lines: running=%d open=%d)",
		s.KnownPeers,
		s.NumSendPackets,
		s.NumSendPacketErrors,
		s.NumReceivedPackets,
		s.NumReceivedPacketErrors,
		s.NumRunningLines,
		s.NumOpenLines,
	)
}

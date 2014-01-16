package telehash

import (
	"fmt"
	"runtime"
	"sync/atomic"
)

type SwitchStats struct {
	KnownPeers    int
	NumGoRoutines int
	NumChannels   int

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

	stats.NumGoRoutines = runtime.NumGoroutine()
	stats.NumChannels = int(atomic.LoadInt32(&s.num_channels))
	stats.KnownPeers = int(atomic.LoadUint32(&s.peers.num_peers))
	stats.NumOpenLines += int(atomic.LoadInt32(&s.num_open_lines))
	stats.NumRunningLines += int(atomic.LoadInt32(&s.num_running_lines))
	s.relay_handler.PopulateStats(&stats)

	return stats
}

func (s SwitchStats) String() string {
	return fmt.Sprintf(
		"(rt: goroutines=%d) (peers: known=%d) (channels: open=%d) (lines: running=%d open=%d) (relay: snd=%d/%d rcv=%d/%d relay=%d/%d)",
		s.NumGoRoutines,
		s.KnownPeers,
		s.NumChannels,
		s.NumRunningLines,
		s.NumOpenLines,
		s.RelayNumSendPackets,
		s.RelayNumSendPacketErrors,
		s.RelayNumReceivedPackets,
		s.RelayNumReceivedPacketErrors,
		s.RelayNumRelayedPackets,
		s.RelayNumRelayedPacketErrors,
	)
}

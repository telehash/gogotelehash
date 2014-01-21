package telehash

import (
	"fmt"
	"github.com/rcrowley/go-metrics"
	"runtime"
	"time"
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

	// reactor
	ReactorQueueDepth   int64
	ReactorExecDuration time.Duration
	ReactorExecLatency  time.Duration
	ReactorDeferCount   int64
}

func (s *Switch) Stats() SwitchStats {
	var (
		stats SwitchStats
	)

	stats.NumGoRoutines = runtime.NumGoroutine()
	stats.NumChannels = int(s.met_channels.Count())
	stats.NumOpenLines = int(s.met_open_lines.Value())
	stats.NumRunningLines = int(s.met_running_lines.Value())
	s.relay_handler.PopulateStats(&stats)
	stats.ReactorQueueDepth = s.met.Get("reactor.queue.depth").(metrics.Counter).Count()
	stats.ReactorExecDuration = time.Duration(s.met.Get("reactor.exec.duration").(metrics.Timer).Mean())
	stats.ReactorExecLatency = time.Duration(s.met.Get("reactor.exec.latency").(metrics.Timer).Mean())
	stats.ReactorDeferCount = s.met.Get("reactor.defer.count").(metrics.Counter).Count()

	return stats
}

func (s SwitchStats) String() string {
	return fmt.Sprintf(
		"(rt: goroutines=%d) (peers: known=%d) (channels: open=%d) (lines: running=%d open=%d)\n(relay: snd=%d/%d rcv=%d/%d relay=%d/%d)\n(reactor: q=%d d=%s l=%s defer=%d)",
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
		s.ReactorQueueDepth,
		s.ReactorExecDuration,
		s.ReactorExecLatency,
		s.ReactorDeferCount,
	)
}

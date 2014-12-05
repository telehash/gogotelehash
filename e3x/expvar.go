package e3x

import (
	"expvar"
)

var (
	statsMap                = expvar.NewMap("e3x")
	statChannelRcvPkt       *expvar.Int
	statChannelRcvPktDrop   *expvar.Int
	statChannelRcvAckInline *expvar.Int
	statChannelRcvAckAdHoc  *expvar.Int
	statChannelSndPkt       *expvar.Int
	statChannelSndAckInline *expvar.Int
	statChannelSndAckAdHoc  *expvar.Int
)

func init() {
	resetStats()
}

func resetStats() {
	statsMap.Init()

	statChannelRcvPkt = new(expvar.Int)
	statChannelRcvPktDrop = new(expvar.Int)
	statChannelRcvAckInline = new(expvar.Int)
	statChannelRcvAckAdHoc = new(expvar.Int)
	statChannelSndPkt = new(expvar.Int)
	statChannelSndAckInline = new(expvar.Int)
	statChannelSndAckAdHoc = new(expvar.Int)

	statsMap.Set("channel.rcv.pkt", statChannelRcvPkt)
	statsMap.Set("channel.rcv.pkt.drop", statChannelRcvPktDrop)
	statsMap.Set("channel.rcv.ack.inline", statChannelRcvAckInline)
	statsMap.Set("channel.rcv.ack.ad-hoc", statChannelRcvAckAdHoc)
	statsMap.Set("channel.snd.pkt", statChannelSndPkt)
	statsMap.Set("channel.snd.ack.inline", statChannelSndAckInline)
	statsMap.Set("channel.snd.ack.ad-hoc", statChannelSndAckAdHoc)
}

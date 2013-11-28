package telehash

type channel_state uint32

const (
	channel_running channel_state = 1 << iota
	channel_open
	channel_snd_end
	channel_rcv_end
	channel_broken
)

func (s channel_state) test(is channel_state, is_not channel_state) bool {
	return state_test(uint32(s), uint32(is), uint32(is_not))
}

func (sptr *channel_state) mod(add, rem channel_state) {
	state_mod((*uint32)(sptr), uint32(add), uint32(rem))
}

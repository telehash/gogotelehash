package telehash

type main_state uint32

const (
	main_running main_state = 1 << iota
	main_terminating
)

func (s main_state) test(is main_state, is_not main_state) bool {
	return state_test(uint32(s), uint32(is), uint32(is_not))
}

func (sptr *main_state) mod(add, rem main_state) {
	state_mod((*uint32)(sptr), uint32(add), uint32(rem))
}

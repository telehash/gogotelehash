package telehash

type line_state uint32

const (
	line_opened line_state = 1 << iota
	line_peering
	line_opening
	line_idle
	line_error
	line_broken
	line_running // is the goroutine running?
	line_peer_down
	line_terminating

	line_active = line_opened | line_opening | line_peering
)

func (l line_state) test(is line_state, is_not line_state) bool {
	return state_test(uint32(l), uint32(is), uint32(is_not))
}

func (lptr *line_state) mod(add, rem line_state) {
	state_mod((*uint32)(lptr), uint32(add), uint32(rem))
}

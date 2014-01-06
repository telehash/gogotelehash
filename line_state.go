package telehash

type line_state uint32

const (
	line_pending line_state = iota
	line_peering
	line_opening
	line_opened
	line_closed
)

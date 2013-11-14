package telehash

import (
	"strconv"
)

type seq_t uint32

func make_seq(i int) seq_t {
	return seq_t(0x80000000 | uint64(i))
}

func (s seq_t) Get() int {
	if s == 0 {
		return -1
	}
	return int(s & 0x7FFFFFFF)
}

func (s seq_t) IsSet() bool {
	return s != 0
}

func (s *seq_t) Set(i int) {
	*s = seq_t(0x80000000 | uint32(i))
}

func (s *seq_t) Clear() {
	*s = 0
}

func (s seq_t) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Itoa(s.Get())), nil
}

func (s *seq_t) UnmarshalJSON(p []byte) error {
	i, err := strconv.Atoi(string(p))
	if err != nil {
		return err
	}
	s.Set(i)
	return nil
}

func (s seq_t) String() string {
	if s.IsSet() {
		return strconv.Itoa(s.Get())
	}
	return "<seq-zero>"
}

func (s seq_t) Incr() seq_t {
	if s == 0 {
		return make_seq(0)
	} else {
		return s + 1
	}
}

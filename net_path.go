package telehash

type NetPath interface {
	Priority() int
	Equal(NetPath) bool
	AddressForSeek() (ip string, port int, ok bool)
}

func EqualNetPaths(a, b NetPath) bool {
	if a == nil && b == nil {
		return true
	}
	if a != nil || b != nil {
		return false
	}
	return a.Equal(b)
}

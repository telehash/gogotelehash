package telehash

func state_test(s, is, is_not uint32) bool {
	if is != 0 && s&is == 0 {
		return false
	}
	if is_not != 0 && s&is_not > 0 {
		return false
	}
	return true
}

func state_mod(lptr *uint32, add, rem uint32) {
	l := *lptr
	l &^= rem
	l |= add
	*lptr = l
}

package cs1a

func fold(p []byte, l int) []byte {
	if len(p)%2 != 0 {
		panic("p must have a length with is a factor of 2")
	}
	if l%2 != 0 {
		panic("l must be a factor of 2")
	}

	// make a copy
	p = append([]byte{}, p...)

	for len(p) > l {
		p = foldHalf(p)
	}

	return p
}

func foldHalf(p []byte) []byte {
	if len(p)%2 != 0 {
		panic("p must have a length with is a factor of 2")
	}

	l := len(p) / 2
	for i, j := 0, l; i < l; {
		p[i] ^= p[j]
		i++
		j++
	}

	return p[:l]
}

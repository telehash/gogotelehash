package telehash

func short_hash(h string) string {
	if len(h) > 8 {
		h = h[:8]
	}
	return h
}

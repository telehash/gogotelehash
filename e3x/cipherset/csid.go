package cipherset

func ExtractCSID(msg []byte) uint8 {
	var (
		csid uint8
		l    = len(msg)
	)

	if l >= 3 && msg[0] == 0 && msg[1] == 1 {
		csid = msg[2]
	}

	return csid
}

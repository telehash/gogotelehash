package telehash

var (
	packet_pool = make(chan *pkt_t, 1024)
	buffer_pool = make(chan []byte, 1024)
)

func packet_pool_acquire() *pkt_t {
	var (
		pkt *pkt_t
	)

	select {
	case pkt = <-packet_pool:
	default:
	}

	if pkt == nil {
		pkt = &pkt_t{}
	}

	pkt.buf = buffer_pool_acquire()

	return pkt
}

func packet_pool_release(pkt *pkt_t) {
	if pkt != nil {
		buffer_pool_release(pkt.buf)

		// reset the packet
		*pkt = pkt_t{}

		select {
		case packet_pool <- pkt:
		default:
		}
	}
}

const buffer_cap = 1500

func buffer_pool_acquire() []byte {
	var (
		buffer []byte
	)

	select {
	case buffer = <-buffer_pool:
	default:
	}

	if buffer == nil {
		buffer = make([]byte, buffer_cap)
	}

	return buffer
}

func buffer_pool_release(buffer []byte) {
	if buffer != nil {
		buffer = buffer[:buffer_cap]
		select {
		case buffer_pool <- buffer:
		default:
		}
	}
}

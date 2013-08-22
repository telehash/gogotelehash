package telehash

type Line struct {
	outKey    ecdh.PrivateKey
	inKey     ecdh.PublicKey
}

func newLine(s *Switch) (*Line, error) {
}

func (line *Line) activate(p *Packet) {
}

func (line *Line) receive(p *Packet) {
}

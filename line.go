package telehash

import "github.com/gokyle/ecdh"

type Line struct {
	sourceId  string
	outKey    ecdh.PrivateKey
	inKey     ecdh.PublicKey
}

func newLine(s *Switch) (*Line, error) {
	return nil, nil
}

func (line *Line) activate(p *Packet) {
}

func (line *Line) receive(p *Packet) {
}

package e3x

func (x *Exchange) traceDroppedHandshake(msg message, handshake cipherset.Handshake, reason string) {
	if tracer.Enabled {
		info := tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"reason":      reason,
		}

		if handshake != nil {
			info["handshake"] = tracer.Info{
				"csid":       fmt.Sprintf("%x", handshake.CSID()),
				"parts":      handshake.Parts(),
				"at":         handshake.At(),
				"public_key": handshake.PublicKey().String(),
			}
		}

		tracer.Emit("exchange.drop.handshake", info)
	}
}

func (x *Exchange) traceReceivedHandshake(msg message, handshake cipherset.Handshake) {
	if tracer.Enabled {
		tracer.Emit("exchange.rcv.handshake", tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"handshake": tracer.Info{
				"csid":       fmt.Sprintf("%x", handshake.CSID()),
				"parts":      handshake.Parts(),
				"at":         handshake.At(),
				"public_key": handshake.PublicKey().String(),
			},
		})
	}
}

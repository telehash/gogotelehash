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

func (x *Exchange) traceError(err error) error {
	if tracer.Enabled && err != nil {
		tracer.Emit("exchange.error", tracer.Info{
			"exchange_id": x.TID,
			"error":       err.Error(),
		})
	}
	return err
}

func (x *Exchange) traceNew() {
	if tracer.Enabled {
		tracer.Emit("exchange.new", tracer.Info{
			"exchange_id": x.TID,
			"endpoint_id": x.endpoint.getTID(),
		})
	}
}

func (x *Exchange) traceStarted() {
	if tracer.Enabled {
		tracer.Emit("exchange.started", tracer.Info{
			"exchange_id": x.TID,
			"peer":        x.remoteIdent.Hashname().String(),
		})
	}
}

func (x *Exchange) traceStopped() {
	if tracer.Enabled {
		tracer.Emit("exchange.stopped", tracer.Info{
			"exchange_id": x.TID,
		})
	}
}

func (x *Exchange) traceDroppedPacket(msg message, pkt *lob.Packet, reason string) {
	if tracer.Enabled {
		info := tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"reason":      reason,
		}

		if pkt != nil {
			info["packet"] = tracer.Info{
				"header": pkt.Header(),
				"body":   base64.StdEncoding.EncodeToString(pkt.Body(nil)),
			}
		}

		tracer.Emit("exchange.rcv.packet", info)
	}
}

func (x *Exchange) traceReceivedPacket(msg message, pkt *lob.Packet) {
	if tracer.Enabled {
		tracer.Emit("exchange.rcv.packet", tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"packet": tracer.Info{
				"header": pkt.Header(),
				"body":   base64.StdEncoding.EncodeToString(pkt.Body(nil)),
			},
		})
	}
}

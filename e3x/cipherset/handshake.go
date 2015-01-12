package cipherset

import (
	"fmt"
	"strconv"

	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/internal/lob"
)

type errInvalidHandshake string

func (e errInvalidHandshake) Error() string {
	return fmt.Sprintf("inavlid handshake: %s", string(e))
}

type KeyHandshake struct {
	CSID     uint8
	Key      []byte
	Parts    map[uint8]string
	Hashname hashname.H
}

func (h *KeyHandshake) Type() string {
	return "key"
}

func (h *KeyHandshake) EncodeHandshake() (*lob.Packet, error) {
	pkt := lob.New(h.Key)
	hdr := pkt.Header()
	hdr.Extra = map[string]interface{}{}

	for csid, part := range h.Parts {
		csidKey := strconv.FormatUint(uint64(csid), 16)
		for len(csidKey) < 2 {
			csidKey = "0" + csidKey
		}

		hdr.Extra[csidKey] = part
	}

	{
		csidKey := strconv.FormatUint(uint64(h.CSID), 16)
		for len(csidKey) < 2 {
			csidKey = "0" + csidKey
		}

		hdr.Extra[csidKey] = true
	}

	return pkt, nil
}

func (h *KeyHandshake) DecodeHandshake(pkt *lob.Packet) error {
	h.Parts = nil

	for k, v := range pkt.Header().Extra {
		csid, err := strconv.ParseUint(k, 16, 8)
		if err != nil {
			return errInvalidHandshake("invalid header")
		}

		switch x := v.(type) {
		case string:
			if h.Parts == nil {
				h.Parts = make(map[uint8]string)
			}
			h.Parts[uint8(csid)] = x

		case bool:
			if x == true {
				h.CSID = uint8(csid)
			} else {
				return errInvalidHandshake("invalid header")
			}

		default:
			return errInvalidHandshake("invalid header")
		}
	}

	h.Key = pkt.Body(nil)
	if len(h.Key) == 0 {
		return errInvalidHandshake("invalid body")
	}

	hn, err := hashname.FromKeyAndIntermediates(h.CSID, h.Key, h.Parts)
	if err != nil {
		return errInvalidHandshake("unable to make hashname")
	}

	h.Hashname = hn

	return nil
}

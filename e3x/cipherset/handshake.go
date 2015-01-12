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
	CSID     CSID
	Key      Key
	Parts    Parts
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
				h.Parts = make(map[CSID]string)
			}
			h.Parts[CSID(csid)] = x

		case bool:
			if x == true {
				h.CSID = CSID(csid)
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

	if h.Parts == nil {
		h.Parts = make(map[CSID]string)
	}
	h.Parts[h.CSID] = h.Key.ToPart()
	h.Hashname = h.Parts.ToHashname()

	return nil
}

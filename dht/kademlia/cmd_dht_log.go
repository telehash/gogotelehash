package kademlia

import (
	"fmt"
	"github.com/telehash/gogotelehash"
	"sort"
	"strings"
	"time"
)

type cmd_dht_log struct {
}

func (cmd *cmd_dht_log) Exec(state interface{}) error {
	var (
		dht   = state.(*DHT)
		links []string
		now   = time.Now()
	)
	dht.logger.Reset(10 * time.Second)

	for _, link := range dht.links {
		links = append(links, fmt.Sprintf("%s (seed=%v age=%s last-seen=%s)", link.peer.Hashname(), link.seed, now.Sub(link.created_at), now.Sub(link.last_seen)))
	}

	sort.Strings(links)

	telehash.Log.Noticef("links: count=%d\n%s", len(links), strings.Join(links, "\n"))
	return nil
}

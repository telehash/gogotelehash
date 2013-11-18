package telehash

import (
	"sync"
	"time"
)

type main_controller struct {
	sw       *Switch
	shutdown chan bool
	wg       sync.WaitGroup
}

func main_controller_open(sw *Switch) (*main_controller, error) {

	h := &main_controller{
		sw:       sw,
		shutdown: make(chan bool, 1),
	}

	h.wg.Add(1)
	go h._loop()

	return h, nil
}

func (c *main_controller) close() {
	c.shutdown <- true
	c.wg.Wait()
}

func (c *main_controller) _loop() {
	defer c.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {

		case <-c.shutdown:
			return

		case now := <-ticker.C:
			c._tick(now)

		}
	}
}

func (c *main_controller) _tick(now time.Time) {

	// auto-ack channels
	// invalidate idle lines (TODO)
	// detect broken lines (TODO)
	c.sw.peers.tick(now)

}

package telehash

import (
	"sync"
	"time"
)

type main_controller struct {
	sw       *Switch
	shutdown chan bool
	wg       sync.WaitGroup

	lines                map[Hashname]*line_t
	get_line_chan        chan cmd_line_get
	register_line_chan   chan *line_t
	unregister_line_chan chan *line_t

	active_lines         map[string]*line_t
	get_active_line_chan chan cmd_line_get_active
	activate_line_chan   chan *line_t
	deactivate_line_chan chan *line_t
}

type cmd_line_get_active struct {
	id    string
	reply chan *line_t
}

type cmd_line_get struct {
	hashname Hashname
	reply    chan *line_t
}

func main_controller_open(sw *Switch) (*main_controller, error) {

	h := &main_controller{
		sw:       sw,
		shutdown: make(chan bool, 1),

		lines:                make(map[Hashname]*line_t),
		get_line_chan:        make(chan cmd_line_get),
		register_line_chan:   make(chan *line_t),
		unregister_line_chan: make(chan *line_t),

		active_lines:         make(map[string]*line_t),
		get_active_line_chan: make(chan cmd_line_get_active),
		activate_line_chan:   make(chan *line_t),
		deactivate_line_chan: make(chan *line_t),
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

		case line := <-c.activate_line_chan:
			c.active_lines[line.prv_key.id] = line
		case line := <-c.deactivate_line_chan:
			delete(c.active_lines, line.prv_key.id)
		case cmd := <-c.get_active_line_chan:
			cmd.reply <- c.active_lines[cmd.id]

		case line := <-c.register_line_chan:
			c.lines[line.peer.addr.hashname] = line
		case line := <-c.unregister_line_chan:
			delete(c.lines, line.peer.addr.hashname)
		case cmd := <-c.get_line_chan:
			cmd.reply <- c.lines[cmd.hashname]

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

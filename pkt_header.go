package telehash

type pkt_hdr_app struct {
	Custom interface{} `json:"_"`
}

type ChannelEndHeader interface {
	End() bool
}

type ChannelErrHeader interface {
	Err() string
}

type channelNetPathHeader interface {
	get_net_path() *net_path
	set_net_path(*net_path)
}

type channel_basic_end_header struct{}

func (c *channel_basic_end_header) End() bool { return true }

type channel_basic_err_header struct {
	err string
}

func (c *channel_basic_err_header) Err() string { return c.err }

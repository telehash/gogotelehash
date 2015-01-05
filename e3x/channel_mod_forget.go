package e3x

// Forgetter exposes the ForgetChannel method
type Forgetter interface {
	// ForgetChannel makes the endpoint drop this channel.
	// This method is ment to be used only when you know what you are doing.
	ForgetChannel(ch *Channel)
}

// ForgetterFromEndpoint returns the Forgetter module for Endpoint.
func ForgetterFromEndpoint(e *Endpoint) Forgetter {
	mod := e.Module(modForgetterKey)
	if mod == nil {
		return nil
	}
	return mod.(*modForgetter)
}

const modForgetterKey = pivateModKey("forgetter")

type modForgetter struct {
	e *Endpoint
}

func (mod *modForgetter) Init() error  { return nil }
func (mod *modForgetter) Start() error { return nil }
func (mod *modForgetter) Stop() error  { return nil }

func (mod *modForgetter) ForgetChannel(ch *Channel) {
	if ch != nil {
		ch.forget()
	}
}

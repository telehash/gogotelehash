package e3x

type Forgetter interface {
	ForgetChannel(ch *Channel)
}

func ForgetterFromEndpoint(e *Endpoint) Forgetter {
	mod := e.Module(modForgetterKey)
	if mod == nil {
		return nil
	}
	return mod.(*modForgetter)
}

const modForgetterKey = modForgetterKeyType("forgetter")

type modForgetterKeyType string

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

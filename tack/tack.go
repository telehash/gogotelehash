package tack

type InvalidTackError string

func (e InvalidTackError) Error() string {
	return "invalid tack: " + string(e)
}

type Tack struct {
	App       string
	Alias     string
	Canonical string
	Token     string
}

func (t *Tack) String() string {
	s := t.App
	if t.Alias != "" {
		s += ":" + t.Alias
	}
	if t.Canonical != "" {
		s += "@" + t.Canonical
	}
	if t.Token != "" {
		s += "/" + t.Token
	}
	return s
}

package uri

import (
	"net/url"
)

type InvalidURIError string

func (e InvalidURIError) Error() string {
	return "invalid uri: " + string(e)
}

type URI struct {
	Protocol  string
	User      string
	Canonical string
	Session   string
	Token     string
}

func (uri *URI) String() string {
	u := url.URL{
		Scheme:   uri.Protocol,
		User:     url.User(uri.User),
		Host:     uri.Canonical,
		Path:     uri.Session,
		Fragment: uri.Token,
	}

	return u.String()
}

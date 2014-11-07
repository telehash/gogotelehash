// Package uri handles the Telehash URI format.
//
// Reference
//
// See: https://github.com/telehash/telehash.org/blob/master/v3/uri.md
package uri

import (
	"net/url"
)

// InvalidURIError is returned when Parse has invalid input
type InvalidURIError string

func (e InvalidURIError) Error() string {
	return "invalid uri: " + string(e)
}

// URI represents a Telehash URI. It can be resolved to an Identity.
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
		Host:     uri.Canonical,
		Path:     uri.Session,
		Fragment: uri.Token,
	}

	if u.Scheme == "" {
		u.Scheme = "mesh"
	}

	if uri.User != "" {
		u.User = url.User(uri.User)
	}

	return u.String()
}

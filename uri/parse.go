package uri

import (
	"net/url"
	"strings"
)

func Parse(rawstr string) (*URI, error) {
	if !strings.Contains(rawstr, "://") {
		rawstr = "mesh://" + rawstr
	}

	u, err := url.Parse(rawstr)
	if err != nil {
		return nil, InvalidURIError(err.Error())
	}

	user := ""
	if u.User != nil {
		user = u.User.Username()
	}

	u.Path = strings.TrimPrefix(u.Path, "/")
	u.Fragment = strings.TrimPrefix(u.Fragment, "#")

	if u.Host == "" {
		return nil, InvalidURIError("missing canonical component")
	}

	return &URI{u.Scheme, user, u.Host, u.Path, u.Fragment}, nil
}

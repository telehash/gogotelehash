package tack

import (
	"bitbucket.org/simonmenke/go-telehash/util/base32util"
)

func Parse(rawstr string) (*Tack, error) {
	app, rest, err := parseApp(rawstr)
	if err != nil {
		return nil, err
	}

	alias, rest, err := parseAlias(rest)
	if err != nil {
		return nil, err
	}

	canonical, token, err := parseCanonical(rest)
	if err != nil {
		return nil, err
	}

	if len(alias) > 0 && alias[0] == '+' {
		data, err := base32util.DecodeString(alias[1:])
		if err == nil {
			alias = string(data)
		}
	}

	if len(token) > 0 && token[0] == '+' {
		data, err := base32util.DecodeString(token[1:])
		if err == nil {
			token = string(data)
		}
	}

	return &Tack{app, alias, canonical, token}, nil
}

func parseApp(rawstr string) (app, rest string, err error) {
	for i, c := range rawstr {
		if c == ':' {
			app = rawstr[:i]
			rest = rawstr[i+1:]

			if len(app) == 0 {
				return "", "", InvalidTackError("missing app component")
			}

			if len(rest) == 0 {
				return "", "", InvalidTackError("missing canonical component")
			}

			return app, rest, nil
		}

		if c == '@' || c == '/' {
			break
		}
	}

	return "", rawstr, nil
}

func parseAlias(rawstr string) (alias, rest string, err error) {
	for i, c := range rawstr {
		if c == '@' {
			alias = rawstr[:i]
			rest = rawstr[i+1:]

			if len(alias) == 0 {
				return "", "", InvalidTackError("missing alias component")
			}

			if len(rest) == 0 {
				return "", "", InvalidTackError("missing canonical component")
			}

			return alias, rest, nil
		}

		if c == '/' {
			break
		}
	}

	return "", rawstr, nil
}

func parseCanonical(rawstr string) (canonical, rest string, err error) {
	var found bool

	for i, c := range rawstr {
		if c == '/' {
			found = true
			canonical = rawstr[:i]
			rest = rawstr[i+1:]

			if len(canonical) == 0 {
				return "", "", InvalidTackError("missing canonical component")
			}

			return canonical, rest, nil
		}
	}

	if !found {
		canonical = rawstr
	}

	if len(canonical) == 0 {
		return "", "", InvalidTackError("missing canonical component")
	}

	return canonical, rest, nil
}

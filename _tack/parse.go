package tack

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
				return "", "", InvalidTackError("missing alias component")
			}

			return app, rest, nil
		}

		if c == '@' {
			// needs alias
			return "", "", InvalidTackError("missing alias component")
		}

		if c == '/' {
			// needs alias
			return "", "", InvalidTackError("missing alias component")
		}
	}

	return "", "", InvalidTackError("missing alias component")
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
			// needs canonical
			return "", "", InvalidTackError("missing canonical component")
		}
	}

	return "", "", InvalidTackError("missing canonical component")
}

func parseCanonical(rawstr string) (canonical, rest string, err error) {
	for i, c := range rawstr {
		if c == '/' {
			canonical = rawstr[:i]
			rest = rawstr[i+1:]

			if len(canonical) == 0 {
				return "", "", InvalidTackError("missing canonical component")
			}

			return canonical, rest, nil
		}
	}

	if len(canonical) == 0 {
		return "", "", InvalidTackError("missing canonical component")
	}

	return canonical, rest, nil
}

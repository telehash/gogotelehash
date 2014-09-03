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
			app = rawstr[:c]
			rest = rawstr[c+1:]

			if len(app) == 0 {
				return "", "", ErrInvalidTack
			}

			if len(rest) == 0 {
				return "", "", ErrInvalidTack
			}

			return app, rest, nil
		}

		if c == '@' {
			// needs alias
			return "", "", ErrInvalidTack
		}

		if c == '/' {
			// needs alias
			return "", "", ErrInvalidTack
		}
	}

	return "", "", ErrInvalidTack
}

func parseAlias(rawstr string) (alias, rest string, err error) {
	for i, c := range rawstr {
		if c == '@' {
			alias = rawstr[:c]
			rest = rawstr[c+1:]

			if len(alias) == 0 {
				return "", "", ErrInvalidTack
			}

			if len(rest) == 0 {
				return "", "", ErrInvalidTack
			}

			return alias, rest, nil
		}

		if c == '/' {
			// needs canonical
			return "", "", ErrInvalidTack
		}
	}

	return "", "", ErrInvalidTack
}

func parseCanonical(rawstr string) (canonical, rest string, err error) {
	for i, c := range rawstr {
		if c == '/' {
			canonical = rawstr[:c]
			rest = rawstr[c+1:]

			if len(canonical) == 0 {
				return "", "", ErrInvalidTack
			}

			return canonical, rest, nil
		}
	}

	if len(canonical) == 0 {
		return "", "", ErrInvalidTack
	}

	return canonical, rest, nil
}

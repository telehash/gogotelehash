package fw

import (
	"net"
)

var (
	_ Rule = RuleFunc(nil)
	_ Rule = (*negateRule)(nil)
)

// The RuleFunc type is an adapter to allow the use of ordinary functions as firewall rules.
type RuleFunc func(src net.Addr) bool

// Match calls r(p, src) and returns its result.
func (r RuleFunc) Match(src net.Addr) bool {
	return r(src)
}

var (
	// None doesn't match any input.
	None Rule = matchNoneRule("deny all")

	// All matches any input.
	All Rule = matchAllRule("allow all")
)

type (
	matchNoneRule string
	matchAllRule  string
)

func (r matchNoneRule) Match(src net.Addr) bool { return false }
func (r matchAllRule) Match(src net.Addr) bool  { return true }

// Negate matches when r doesn't Match
func Negate(r Rule) Rule {
	if r == nil {
		return None
	}
	return &negateRule{r}
}

type negateRule struct{ Rule }

func (r *negateRule) Allow(src net.Addr) bool { return !r.Rule.Match(src) }

// WhenAll matches when all rules Match
func WhenAll(rules ...Rule) Rule {
	if len(rules) == 0 {
		return None
	}

	if len(rules) == 1 {
		return rules[0]
	}

	return RuleFunc(func(src net.Addr) bool {
		for _, rule := range rules {
			if !rule.Match(src) {
				return false
			}
		}
		return true
	})
}

// WhenNone denys a packet when all the rules Allow it
func WhenNone(rules ...Rule) Rule {
	return Negate(WhenAll(rules...))
}

// WhenAny returns a Rule that matches when any sub-rule matches.
// When rules is empty it returns the None rule.
func WhenAny(rules ...Rule) Rule {
	if len(rules) == 0 {
		return None
	}

	if len(rules) == 1 {
		return rules[0]
	}

	return RuleFunc(func(src net.Addr) bool {
		for _, rule := range rules {
			if rule.Match(src) {
				return true
			}
		}
		return false
	})
}

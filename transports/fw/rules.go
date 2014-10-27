package fw

import (
	"github.com/telehash/gogotelehash/transports"
)

var (
	_ Rule = RuleFunc(nil)
	_ Rule = (*negateRule)(nil)
)

type RuleFunc func(p []byte, src transports.Addr) bool

func (r RuleFunc) Match(p []byte, src transports.Addr) bool {
	return r(p, src)
}

var (
	None Rule = matchNoneRule("deny all")
	All  Rule = matchAllRule("allow all")
)

type (
	matchNoneRule string
	matchAllRule  string
)

func (r matchNoneRule) Match(p []byte, src transports.Addr) bool { return false }
func (r matchAllRule) Match(p []byte, src transports.Addr) bool  { return true }

// Negate matches when r doesn't Match
func Negate(r Rule) Rule {
	if r == nil {
		return None
	}
	return &negateRule{r}
}

type negateRule struct{ Rule }

func (r *negateRule) Allow(p []byte, src transports.Addr) bool { return !r.Rule.Match(p, src) }

// WhenAll matches when all rules Match
func WhenAll(rules ...Rule) Rule {
	if len(rules) == 0 {
		return None
	}

	if len(rules) == 1 {
		return rules[0]
	}

	return RuleFunc(func(p []byte, src transports.Addr) bool {
		for _, rule := range rules {
			if !rule.Match(p, src) {
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

func WhenAny(rules ...Rule) Rule {
	if len(rules) == 0 {
		return None
	}

	if len(rules) == 1 {
		return rules[0]
	}

	return RuleFunc(func(p []byte, src transports.Addr) bool {
		for _, rule := range rules {
			if rule.Match(p, src) {
				return true
			}
		}
		return false
	})
}

func From(addr transports.Addr) Rule {
	return RuleFunc(func(p []byte, src transports.Addr) bool {
		return transports.EqualAddr(src, addr)
	})
}

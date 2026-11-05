package router

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DomainMatcher matches domain names using Xray semantics:
// full (exact), suffix ("domain:" — itself and subdomains), keyword
// (substring) and regexp.
type DomainMatcher struct {
	full     map[string]struct{}
	suffix   map[string]struct{}
	keywords []string
	regexps  []*regexp.Regexp
}

func newDomainMatcher() *DomainMatcher {
	return &DomainMatcher{full: map[string]struct{}{}, suffix: map[string]struct{}{}}
}

func (m *DomainMatcher) add(typ int, value string) error {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	switch typ {
	case domainFull:
		m.full[value] = struct{}{}
	case domainSuffix:
		m.suffix[value] = struct{}{}
	case domainPlain:
		m.keywords = append(m.keywords, value)
	case domainRegex:
		re, err := regexp.Compile(value)
		if err != nil {
			return fmt.Errorf("invalid regexp %q: %w", value, err)
		}
		m.regexps = append(m.regexps, re)
	default:
		return fmt.Errorf("unknown domain type %d", typ)
	}
	return nil
}

func (m *DomainMatcher) empty() bool {
	return len(m.full) == 0 && len(m.suffix) == 0 && len(m.keywords) == 0 && len(m.regexps) == 0
}

// Match reports whether domain (lower-case, no trailing dot) matches.
func (m *DomainMatcher) Match(domain string) bool {
	if _, ok := m.full[domain]; ok {
		return true
	}
	for s := domain; ; {
		if _, ok := m.suffix[s]; ok {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	for _, k := range m.keywords {
		if strings.Contains(domain, k) {
			return true
		}
	}
	for _, re := range m.regexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

// ipRange is an inclusive address range.
type ipRange struct{ from, to netip.Addr }

// ipSet is a sorted, merged list of ranges searched with binary search.
type ipSet struct{ ranges []ipRange }

func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().As16()
	start := 0
	if p.Addr().Is4() {
		start = 12
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	for i := 15; i >= start && hostBits > 0; i-- {
		if hostBits >= 8 {
			b[i] = 0xff
			hostBits -= 8
		} else {
			b[i] |= byte(1<<hostBits) - 1
			hostBits = 0
		}
	}
	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		a = a.Unmap()
	}
	return a
}

func newIPSet(prefixes []netip.Prefix) *ipSet {
	rs := make([]ipRange, 0, len(prefixes))
	for _, p := range prefixes {
		rs = append(rs, ipRange{p.Masked().Addr(), lastAddr(p)})
	}
	slices.SortFunc(rs, func(a, b ipRange) int { return a.from.Compare(b.from) })
	merged := rs[:0]
	for _, r := range rs {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			if last.to.Is4() == r.from.Is4() && (r.from.Compare(last.to) <= 0 || last.to.Next() == r.from) {
				if r.to.Compare(last.to) > 0 {
					last.to = r.to
				}
				continue
			}
		}
		merged = append(merged, r)
	}
	return &ipSet{ranges: merged}
}

func (s *ipSet) Contains(a netip.Addr) bool {
	a = a.Unmap()
	i, found := slices.BinarySearchFunc(s.ranges, a, func(r ipRange, t netip.Addr) int {
		return r.from.Compare(t)
	})
	if found {
		return true
	}
	if i == 0 {
		return false
	}
	r := s.ranges[i-1]
	return r.from.Is4() == a.Is4() && a.Compare(r.to) <= 0
}

// IPMatcher is an OR of sets; an inverted set matches addresses outside it.
type IPMatcher struct {
	sets []ipSetRef
}

type ipSetRef struct {
	set     *ipSet
	inverse bool
}

func (m *IPMatcher) Match(a netip.Addr) bool {
	for _, s := range m.sets {
		if s.set.Contains(a) != s.inverse {
			return true
		}
	}
	return false
}

// PortSet is a list of inclusive port ranges.
type PortSet []portRange

type portRange struct{ from, to uint16 }

// ParsePorts parses "443", "1000-2000" or "80,443,1000-2000".
func ParsePorts(s string) (PortSet, error) {
	var ps PortSet
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		from, to, isRange := strings.Cut(part, "-")
		a, err := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			b, err = strconv.ParseUint(strings.TrimSpace(to), 10, 16)
			if err != nil || b < a {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		ps = append(ps, portRange{uint16(a), uint16(b)})
	}
	return ps, nil
}

func (ps PortSet) Match(p uint16) bool {
	for _, r := range ps {
		if p >= r.from && p <= r.to {
			return true
		}
	}
	return false
}

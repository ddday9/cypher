// Package router picks an outbound for each connection using Xray-style
// rules and Xray-compatible geosite.dat / geoip.dat files.
package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/netx"
)

// Metadata describes a connection being routed.
type Metadata struct {
	InboundTag string
	Dest       netx.Destination
	// Process is the executable path of the program that opened the
	// connection, if known (see NeedsProcess).
	Process string
}

type rule struct {
	domain   *DomainMatcher
	ip       *IPMatcher
	ports    PortSet
	networks map[string]bool
	inbounds map[string]bool
	process  []string // lower-case file names or full paths
	outbound string
	desc     string
}

// Resolver looks up IP addresses for IPIfNonMatch.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Router selects an outbound tag for a connection.
type Router struct {
	rules        []*rule
	defaultTag   string
	ipIfNonMatch bool
	resolver     Resolver
}

// New compiles routing rules. geosite/geoip paths must already be resolved.
func New(cfg config.RoutingConfig, defaultTag string, geo *GeoLoader) (*Router, error) {
	r := &Router{defaultTag: defaultTag, resolver: net.DefaultResolver}
	if cfg.Default != "" {
		r.defaultTag = cfg.Default
	}
	switch strings.ToLower(cfg.DomainStrategy) {
	case "", "asis":
	case "ipifnonmatch":
		r.ipIfNonMatch = true
	default:
		return nil, fmt.Errorf("unknown domainStrategy %q (use AsIs or IPIfNonMatch)", cfg.DomainStrategy)
	}
	for i, rc := range cfg.Rules {
		ru, err := compileRule(rc, geo)
		if err != nil {
			return nil, fmt.Errorf("routing rule #%d: %w", i+1, err)
		}
		r.rules = append(r.rules, ru)
	}
	return r, nil
}

func compileRule(rc config.RuleConfig, geo *GeoLoader) (*rule, error) {
	if rc.Outbound == "" {
		return nil, fmt.Errorf("missing outbound")
	}
	ru := &rule{outbound: rc.Outbound}
	var desc []string
	if len(rc.Domain) > 0 {
		m := newDomainMatcher()
		for _, d := range rc.Domain {
			if err := addDomain(m, d, geo); err != nil {
				return nil, err
			}
		}
		ru.domain = m
		desc = append(desc, "domain="+strings.Join(rc.Domain, ","))
	}
	if len(rc.IP) > 0 {
		m := &IPMatcher{}
		var plain []netip.Prefix
		for _, s := range rc.IP {
			if err := addIP(m, &plain, s, geo); err != nil {
				return nil, err
			}
		}
		if len(plain) > 0 {
			m.sets = append(m.sets, ipSetRef{set: newIPSet(plain)})
		}
		ru.ip = m
		desc = append(desc, "ip="+strings.Join(rc.IP, ","))
	}
	if rc.Port != "" {
		ps, err := ParsePorts(string(rc.Port))
		if err != nil {
			return nil, err
		}
		ru.ports = ps
		desc = append(desc, "port="+string(rc.Port))
	}
	if rc.Network != "" {
		ru.networks = map[string]bool{}
		for n := range strings.SplitSeq(rc.Network, ",") {
			n = strings.ToLower(strings.TrimSpace(n))
			if n != "tcp" && n != "udp" {
				return nil, fmt.Errorf("unknown network %q", n)
			}
			ru.networks[n] = true
		}
		desc = append(desc, "network="+rc.Network)
	}
	if len(rc.InboundTag) > 0 {
		ru.inbounds = map[string]bool{}
		for _, t := range rc.InboundTag {
			ru.inbounds[t] = true
		}
		desc = append(desc, "inboundTag="+strings.Join(rc.InboundTag, ","))
	}
	for _, p := range rc.Process {
		p = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, `\`, "/")))
		if p != "" {
			ru.process = append(ru.process, p)
		}
	}
	if len(ru.process) > 0 {
		desc = append(desc, "process="+strings.Join(rc.Process, ","))
	}
	if len(desc) == 0 {
		return nil, fmt.Errorf("rule has no conditions")
	}
	ru.desc = strings.Join(desc, " ")
	return ru, nil
}

func addDomain(m *DomainMatcher, s string, geo *GeoLoader) error {
	prefix, value, hasPrefix := strings.Cut(s, ":")
	if !hasPrefix {
		return m.add(domainPlain, s)
	}
	switch prefix {
	case "geosite":
		code, attr, _ := strings.Cut(value, "@")
		domains, err := geo.Site(code)
		if err != nil {
			return err
		}
		attr = strings.ToLower(attr)
		added := 0
		for _, d := range domains {
			if attr != "" && !containsStr(d.attrs, attr) {
				continue
			}
			if err := m.add(d.typ, d.value); err != nil {
				return err
			}
			added++
		}
		if added == 0 {
			return fmt.Errorf("%s matched no domains", s)
		}
		return nil
	case "domain":
		return m.add(domainSuffix, value)
	case "full":
		return m.add(domainFull, value)
	case "keyword":
		return m.add(domainPlain, value)
	case "regexp":
		return m.add(domainRegex, value)
	default:
		// Not a known prefix: treat the whole string as a keyword (Xray does
		// the same for plain strings).
		return m.add(domainPlain, s)
	}
}

func addIP(m *IPMatcher, plain *[]netip.Prefix, s string, geo *GeoLoader) error {
	if code, ok := strings.CutPrefix(s, "geoip:"); ok {
		inverse := false
		if c, neg := strings.CutPrefix(code, "!"); neg {
			code, inverse = c, true
		}
		g, err := geo.IP(code)
		if err != nil {
			return err
		}
		m.sets = append(m.sets, ipSetRef{set: newIPSet(g.prefixes), inverse: inverse != g.reverse})
		return nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", s)
		}
		*plain = append(*plain, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr())))
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP %q", s)
	}
	a = a.Unmap()
	*plain = append(*plain, netip.PrefixFrom(a, a.BitLen()))
	return nil
}

func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// match evaluates a rule. ips are the resolved addresses (nil if none).
func (ru *rule) match(md Metadata, ips []netip.Addr) bool {
	if ru.inbounds != nil && !ru.inbounds[md.InboundTag] {
		return false
	}
	if ru.process != nil && !matchProcess(ru.process, md.Process) {
		return false
	}
	if ru.networks != nil && !ru.networks[md.Dest.Network] {
		return false
	}
	if ru.ports != nil && !ru.ports.Match(md.Dest.Port) {
		return false
	}
	if ru.domain != nil {
		if !md.Dest.IsDomain() || !ru.domain.Match(md.Dest.Host) {
			return false
		}
	}
	if ru.ip != nil {
		if a, ok := md.Dest.Addr(); ok {
			ips = []netip.Addr{a}
		}
		hit := false
		for _, a := range ips {
			if ru.ip.Match(a) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// Route returns the outbound tag for a connection.
func (r *Router) Route(ctx context.Context, md Metadata) string {
	for _, ru := range r.rules {
		if ru.match(md, nil) {
			slog.Debug("route", "dest", md.Dest.String(), "rule", ru.desc, "outbound", ru.outbound)
			return ru.outbound
		}
	}
	if r.ipIfNonMatch && md.Dest.IsDomain() {
		ips, err := r.resolver.LookupNetIP(ctx, "ip", md.Dest.Host)
		if err == nil && len(ips) > 0 {
			for i := range ips {
				ips[i] = ips[i].Unmap()
			}
			for _, ru := range r.rules {
				if ru.ip != nil && ru.match(md, ips) {
					slog.Debug("route", "dest", md.Dest.String(), "resolved", ips, "rule", ru.desc, "outbound", ru.outbound)
					return ru.outbound
				}
			}
		}
	}
	slog.Debug("route", "dest", md.Dest.String(), "outbound", r.defaultTag, "rule", "default")
	return r.defaultTag
}

func matchProcess(want []string, path string) bool {
	if path == "" {
		return false
	}
	full := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	name := full[strings.LastIndexByte(full, '/')+1:]
	for _, w := range want {
		if strings.Contains(w, "/") {
			if full == w {
				return true
			}
		} else if name == w {
			return true
		}
	}
	return false
}

// NeedsProcess reports whether any rule matches by process, so callers only
// pay for the owner lookup when it matters.
func (r *Router) NeedsProcess() bool {
	for _, ru := range r.rules {
		if ru.process != nil {
			return true
		}
	}
	return false
}

// DefaultTag returns the outbound used when no rule matches.
func (r *Router) DefaultTag() string { return r.defaultTag }

// OutboundTags returns the outbound tags referenced by rules.
func (r *Router) OutboundTags() []string {
	var tags []string
	for _, ru := range r.rules {
		tags = append(tags, ru.outbound)
	}
	return tags
}

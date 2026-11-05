package router

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// The .dat files are Xray/V2Ray protobuf messages (app/router/config.proto):
//
//	GeoSiteList { repeated GeoSite entry = 1; }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//	Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//	Attribute   { string key = 1; oneof { bool bool_value = 2; int64 int_value = 3; } }
//	GeoIPList   { repeated GeoIP entry = 1; }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//	CIDR        { bytes ip = 1; uint32 prefix = 2; }
//
// They are decoded directly with protowire, so no generated code is needed.

// Domain types as defined by Xray.
const (
	domainPlain  = 0 // substring
	domainRegex  = 1
	domainSuffix = 2 // "domain:" — the domain and all subdomains
	domainFull   = 3
)

type geoDomain struct {
	typ   int
	value string
	attrs []string
}

// GeoLoader lazily reads geosite/geoip files and caches decoded entries.
type GeoLoader struct {
	sitePath, ipPath string
	siteData, ipData []byte
	sites            map[string][]geoDomain
	ips              map[string]geoIP
}

type geoIP struct {
	prefixes []netip.Prefix
	reverse  bool
}

// NewGeoLoader creates a loader. Files are only opened when first needed.
func NewGeoLoader(sitePath, ipPath string) *GeoLoader {
	return &GeoLoader{sitePath: sitePath, ipPath: ipPath,
		sites: map[string][]geoDomain{}, ips: map[string]geoIP{}}
}

var errNotFound = errors.New("not found")

// forEachEntry iterates field-1 entries of a *List message, calling fn with
// the entry's country code and raw bytes.
func forEachEntry(data []byte, fn func(code string, entry []byte) (stop bool)) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		if num != 1 || typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return protowire.ParseError(n)
			}
			data = data[n:]
			continue
		}
		entry, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		code, err := entryCode(entry)
		if err != nil {
			return err
		}
		if fn(code, entry) {
			return nil
		}
	}
	return nil
}

func entryCode(entry []byte) (string, error) {
	for len(entry) > 0 {
		num, typ, n := protowire.ConsumeTag(entry)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		entry = entry[n:]
		if num == 1 && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(entry)
			if n < 0 {
				return "", protowire.ParseError(n)
			}
			return strings.ToLower(string(v)), nil
		}
		n = protowire.ConsumeFieldValue(num, typ, entry)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		entry = entry[n:]
	}
	return "", nil
}

// fields calls fn for every top-level field of msg.
func fields(msg []byte, fn func(num protowire.Number, typ protowire.Type, val []byte, v uint64)) error {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			return protowire.ParseError(n)
		}
		msg = msg[n:]
		switch typ {
		case protowire.BytesType:
			b, n := protowire.ConsumeBytes(msg)
			if n < 0 {
				return protowire.ParseError(n)
			}
			fn(num, typ, b, 0)
			msg = msg[n:]
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(msg)
			if n < 0 {
				return protowire.ParseError(n)
			}
			fn(num, typ, nil, v)
			msg = msg[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, msg)
			if n < 0 {
				return protowire.ParseError(n)
			}
			msg = msg[n:]
		}
	}
	return nil
}

func load(path string, cache *[]byte) ([]byte, error) {
	if *cache != nil {
		return *cache, nil
	}
	if path == "" {
		return nil, errors.New("file path is not configured")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	*cache = b
	return b, nil
}

// Site returns the domains of a geosite list (e.g. "google", "category-ru").
func (g *GeoLoader) Site(code string) ([]geoDomain, error) {
	code = strings.ToLower(code)
	if d, ok := g.sites[code]; ok {
		return d, nil
	}
	data, err := load(g.sitePath, &g.siteData)
	if err != nil {
		return nil, fmt.Errorf("geosite: %w", err)
	}
	var found []byte
	err = forEachEntry(data, func(c string, entry []byte) bool {
		if c == code {
			found = entry
			return true
		}
		return false
	})
	if err != nil {
		return nil, fmt.Errorf("geosite %s: %w", g.sitePath, err)
	}
	if found == nil {
		return nil, fmt.Errorf("geosite:%s %w in %s", code, errNotFound, g.sitePath)
	}
	var domains []geoDomain
	var perr error
	err = fields(found, func(num protowire.Number, typ protowire.Type, val []byte, _ uint64) {
		if num != 2 || typ != protowire.BytesType {
			return
		}
		var d geoDomain
		if e := fields(val, func(num protowire.Number, typ protowire.Type, val []byte, v uint64) {
			switch {
			case num == 1 && typ == protowire.VarintType:
				d.typ = int(v)
			case num == 2 && typ == protowire.BytesType:
				d.value = strings.ToLower(string(val))
			case num == 3 && typ == protowire.BytesType:
				fields(val, func(num protowire.Number, typ protowire.Type, val []byte, _ uint64) {
					if num == 1 && typ == protowire.BytesType {
						d.attrs = append(d.attrs, strings.ToLower(string(val)))
					}
				})
			}
		}); e != nil {
			perr = e
		}
		domains = append(domains, d)
	})
	if err == nil {
		err = perr
	}
	if err != nil {
		return nil, fmt.Errorf("geosite:%s: %w", code, err)
	}
	g.sites[code] = domains
	return domains, nil
}

// IP returns the prefixes of a geoip list (e.g. "ru", "private").
func (g *GeoLoader) IP(code string) (geoIP, error) {
	code = strings.ToLower(code)
	if v, ok := g.ips[code]; ok {
		return v, nil
	}
	data, err := load(g.ipPath, &g.ipData)
	if err != nil {
		return geoIP{}, fmt.Errorf("geoip: %w", err)
	}
	var found []byte
	err = forEachEntry(data, func(c string, entry []byte) bool {
		if c == code {
			found = entry
			return true
		}
		return false
	})
	if err != nil {
		return geoIP{}, fmt.Errorf("geoip %s: %w", g.ipPath, err)
	}
	if found == nil {
		return geoIP{}, fmt.Errorf("geoip:%s %w in %s", code, errNotFound, g.ipPath)
	}
	var res geoIP
	var perr error
	err = fields(found, func(num protowire.Number, typ protowire.Type, val []byte, v uint64) {
		switch {
		case num == 3 && typ == protowire.VarintType:
			res.reverse = v != 0
		case num == 2 && typ == protowire.BytesType:
			var ip []byte
			var bits uint64
			fields(val, func(num protowire.Number, typ protowire.Type, val []byte, v uint64) {
				switch {
				case num == 1 && typ == protowire.BytesType:
					ip = val
				case num == 2 && typ == protowire.VarintType:
					bits = v
				}
			})
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				perr = fmt.Errorf("bad CIDR address of length %d", len(ip))
				return
			}
			if addr.Is4In6() && bits >= 96 {
				addr, bits = addr.Unmap(), bits-96
			}
			p, err := addr.Prefix(int(bits))
			if err != nil {
				perr = err
				return
			}
			res.prefixes = append(res.prefixes, p)
		}
	})
	if err == nil {
		err = perr
	}
	if err != nil {
		return geoIP{}, fmt.Errorf("geoip:%s: %w", code, err)
	}
	g.ips[code] = res
	return res, nil
}

// UsedFiles returns the geo files that were actually read.
func (g *GeoLoader) UsedFiles() []string {
	var files []string
	if g.siteData != nil {
		files = append(files, g.sitePath)
	}
	if g.ipData != nil {
		files = append(files, g.ipPath)
	}
	return files
}

// Categories returns the category names in a geosite.dat or geoip.dat file
// (lower case, sorted), for suggestions in the rule editor.
func Categories(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	err = forEachEntry(data, func(code string, _ []byte) bool {
		if code != "" {
			out = append(out, strings.ToLower(code))
		}
		return false
	})
	sort.Strings(out)
	return slices.Compact(out), err
}

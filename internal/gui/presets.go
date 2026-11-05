package gui

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/ddday9/cypher/internal/config"
)

// Preset is a ready-made routing scheme.
type Preset struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Rules       []config.RuleConfig `json:"rules"`
	Default     string              `json:"default"`
}

// Presets use categories of the runetfreedom/russia-v2ray-rules-dat files.
var Presets = []Preset{
	{
		ID: "smart", Name: "Россия напрямую",
		Description: "Российские сайты и сервисы — напрямую, реклама блокируется, всё остальное — через VPN.",
		Rules: []config.RuleConfig{
			{Domain: []string{"geosite:category-ads-all"}, Outbound: "block"},
			{Domain: []string{"geosite:private", "geosite:category-ru", "domain:ru", "domain:xn--p1ai", "domain:su"}, Outbound: "direct"},
			{IP: []string{"geoip:private", "geoip:ru"}, Outbound: "direct"},
		},
		Default: "proxy",
	},
	{
		ID: "blocked", Name: "Только заблокированное",
		Description: "Через VPN идут только заблокированные в России ресурсы, остальное — напрямую.",
		Rules: []config.RuleConfig{
			{Domain: []string{"geosite:category-ads-all"}, Outbound: "block"},
			{Domain: []string{"geosite:ru-blocked"}, Outbound: "proxy"},
			{IP: []string{"geoip:ru-blocked"}, Outbound: "proxy"},
		},
		Default: "direct",
	},
	{
		ID: "global", Name: "Всё через VPN",
		Description: "Весь трафик через VPN, кроме локальной сети.",
		Rules: []config.RuleConfig{
			{IP: []string{"geoip:private"}, Outbound: "direct"},
		},
		Default: "proxy",
	},
	{
		ID: "custom", Name: "Только мои правила",
		Description: "Работают только ваши правила и приложения; остальное — по выбранному действию.",
		Default:     "proxy",
	},
}

var ruleTypes = map[string]bool{
	"domain": true, "full": true, "keyword": true, "geosite": true,
	"ip": true, "geoip": true, "port": true, "process": true,
}

// compileUserRules turns editor lines into routing rules. Values of one line
// are alternatives (OR).
func compileUserRules(in []UserRule) ([]config.RuleConfig, error) {
	var out []config.RuleConfig
	for i, r := range in {
		if !ruleTypes[r.Type] {
			return nil, fmt.Errorf("правило %d: неизвестный тип %q", i+1, r.Type)
		}
		switch r.Action {
		case "proxy", "direct", "block":
		default:
			return nil, fmt.Errorf("правило %d: действие должно быть proxy, direct или block", i+1)
		}
		vals := strings.FieldsFunc(r.Value, func(c rune) bool { return c == ',' || c == ';' || unicode.IsSpace(c) })
		if r.Type == "process" {
			// File names may contain spaces only as part of a full path.
			vals = nil
			for v := range strings.SplitSeq(r.Value, ",") {
				if v = strings.TrimSpace(v); v != "" {
					vals = append(vals, v)
				}
			}
		}
		if len(vals) == 0 {
			return nil, fmt.Errorf("правило %d: пустое значение", i+1)
		}
		rc := config.RuleConfig{Outbound: r.Action}
		for _, v := range vals {
			switch r.Type {
			case "domain", "full", "keyword", "geosite":
				rc.Domain = append(rc.Domain, r.Type+":"+strings.TrimPrefix(strings.ToLower(v), r.Type+":"))
			case "ip":
				rc.IP = append(rc.IP, v)
			case "geoip":
				rc.IP = append(rc.IP, "geoip:"+strings.TrimPrefix(strings.ToLower(v), "geoip:"))
			case "process":
				rc.Process = append(rc.Process, v)
			}
		}
		if r.Type == "port" {
			rc.Port = config.PortList(strings.Join(vals, ","))
		}
		out = append(out, rc)
	}
	return out, nil
}

// routingRules assembles the rule list: apps and user rules first, then the
// advanced JSON rules, then the preset.
func routingRules(s Settings) ([]config.RuleConfig, string, error) {
	user, err := compileUserRules(s.UserRules)
	if err != nil {
		return nil, "", err
	}
	// Application rules go first so that "dota2.exe → direct" wins over a
	// domain rule for the same traffic.
	var rules []config.RuleConfig
	for _, pass := range []bool{true, false} {
		for _, r := range user {
			if (len(r.Process) > 0) == pass {
				rules = append(rules, r)
			}
		}
	}
	rules = append(rules, s.CustomRules...)
	p := presetByID(s.Routing)
	def := p.Default
	if p.ID == "custom" {
		if s.DefaultAction != "" {
			def = s.DefaultAction
		}
	} else {
		rules = append(rules, p.Rules...)
	}
	return rules, def, nil
}

func presetByID(id string) Preset {
	for _, p := range Presets {
		if p.ID == id {
			return p
		}
	}
	return Presets[0]
}

package gui

import "github.com/ddday9/cypher/internal/config"

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
		ID: "custom", Name: "Свои правила",
		Description: "Правила в формате Xray: domain, ip, port, network → proxy, direct или block.",
		Default:     "proxy",
	},
}

func presetByID(id string) Preset {
	for _, p := range Presets {
		if p.ID == id {
			return p
		}
	}
	return Presets[0]
}

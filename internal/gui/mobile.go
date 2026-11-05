package gui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"strings"
	"sync"

	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/procinfo"
)

// Mobile is implemented by the Android app (see android/ and mobile/). With
// it, nevio runs inside the app: the UI talks to the API in process (no
// local HTTP server, so other apps find no open port), "Весь трафик" is the
// system VPN (VpnService), and "Прокси" is a SOCKS5 proxy with a password.
type Mobile interface {
	// OpenTUN starts the system VPN with settings (VPNSettings as JSON) and
	// returns its file descriptor, which cypher then owns.
	OpenTUN(settings string) (int, error)
	// CloseTUN stops the system VPN.
	CloseTUN()
	// Apps lists installed apps as JSON: [{"name": package, "label": label}].
	Apps() string
	// KeepAlive keeps the app running in the background while the proxy
	// mode is on (a VPN keeps it alive by itself).
	KeepAlive(on bool)
}

var (
	mobileMu sync.Mutex
	mobile   Mobile
)

// SetMobile installs the Android platform; call it before NewApp.
func SetMobile(m Mobile) {
	mobileMu.Lock()
	mobile = m
	mobileMu.Unlock()
}

func getMobile() Mobile {
	mobileMu.Lock()
	defer mobileMu.Unlock()
	return mobile
}

// IsMobile reports whether nevio runs inside the Android app.
func IsMobile() bool { return getMobile() != nil }

// VPNSettings is what the Android app needs to build the VpnService.
type VPNSettings struct {
	Address4 string `json:"address4"`
	Address6 string `json:"address6"`
	DNS      string `json:"dns"`
	MTU      int    `json:"mtu"`
	// Apps in Disallowed bypass the VPN completely: their traffic goes
	// straight to the network and, for them, no VPN is the active network.
	// With Allowed set, only those apps use the VPN (Disallowed is ignored).
	Allowed    []string `json:"allowed,omitempty"`
	Disallowed []string `json:"disallowed,omitempty"`
}

// The VPN's addresses (the TUN inbound defaults) and the DNS server inside it.
const (
	mobileAddr4 = "172.19.0.1/30"
	mobileDNS   = "172.19.0.2"
	mobileAddr6 = "fdfe:dcba:9876::1/126"
	mobileMTU   = 1500
)

// RussianApps are kept out of the VPN by default on Android (Settings.HideRuApps):
// government, banking, marketplace, operator and messenger apps that may
// check whether a VPN is on, or report it. For an app outside the VPN the
// system shows no VPN as its active network, and the app sees your real IP.
var RussianApps = []string{
	// Government and public services
	"ru.rostel", "ru.gosuslugi.mobile", "ru.gosuslugi.goskey", "ru.fns.lkfl", "ru.mos.app",
	"ru.mos.polls", "ru.pfr.mobile", "ru.sfr.app", "ru.nalog.www", "ru.mvd.app",
	"com.gosuslugi.dom", "ru.rzd.pass", "ru.mos.transport", "ru.mos.parking",
	// Banks and payments
	"ru.sberbankmobile", "ru.sberbank.sberbankid", "com.idamob.tinkoff.android",
	"ru.tinkoff.investing", "ru.vtb24.mobilebanking.android", "ru.alfabank.mobile.android",
	"ru.gazprombank.android.mobilebank.app", "ru.raiffeisennews", "ru.psbank.online",
	"ru.rosbank.android", "com.openbank", "ru.sovcomcard.halva.v1", "ru.mkb.mobile",
	"ru.pochtabank.pochtaapp", "ru.rshb.dbo", "ru.nspk.mirpay", "ru.nspk.sbpay",
	"com.yandex.bank", "ru.ozon.fintech.finance", "ru.foodfox.client",
	// Marketplaces and services
	"ru.ozon.app.android", "com.wildberries.ru", "ru.avito.android", "ru.yandex.taxi",
	"ru.yandex.market", "com.yandex.lavka", "ru.yandex.searchplugin", "com.yandex.browser",
	"ru.yandex.yandexmaps", "ru.yandex.music", "ru.kinopoisk", "ru.yandex.mail",
	"ru.dublgis.dgismobile", "ru.vk.store", "ru.cian.main", "ru.megamarket.marketplace",
	// Operators
	"ru.mts.mymts", "ru.megafon.mlk", "ru.beeline.services", "ru.tele2.mytele2",
	"ru.yota.android", "ru.rt.lk",
	// Messengers and social networks
	"ru.oneme.app", "com.vkontakte.android", "ru.ok.android", "ru.mail.mailapp",
	"com.vk.vkvideo", "ru.vk.calls", "ru.mail.cloud",
}

// ensureMobileDefaults fills in Android-only settings on first start.
func ensureMobileDefaults(st *State) {
	s := &st.Settings
	if !s.MobileInit {
		s.MobileInit = true
		s.HideRuApps = true
		s.Mode = "tun"
	}
	if s.ProxyPort == 0 {
		// A random high port with a password: an app that scans local
		// ports finds nothing at the usual 1080/10808, and cannot use it.
		s.ProxyPort = 20000 + mrand.IntN(40000)
	}
	if s.ProxyUser == "" || s.ProxyPass == "" {
		var b [12]byte
		rand.Read(b[:])
		s.ProxyUser = hex.EncodeToString(b[:4])
		s.ProxyPass = hex.EncodeToString(b[4:])
	}
}

// mobileVPN builds the VpnService settings from the app rules.
func mobileVPN(s Settings) VPNSettings {
	v := VPNSettings{Address4: mobileAddr4, Address6: mobileAddr6, DNS: mobileDNS, MTU: mobileMTU}
	seen := map[string]bool{}
	add := func(list *[]string, pkg string) {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" && !seen[pkg] {
			seen[pkg] = true
			*list = append(*list, pkg)
		}
	}
	for _, r := range s.UserRules {
		if r.Type != "process" {
			continue
		}
		for _, pkg := range strings.Split(r.Value, ",") {
			switch {
			case s.AppScope == "selected" && r.Action == "proxy":
				add(&v.Allowed, pkg)
			case s.AppScope != "selected" && r.Action == "direct":
				add(&v.Disallowed, pkg)
			}
		}
	}
	if s.AppScope != "selected" && s.HideRuApps {
		for _, pkg := range RussianApps {
			add(&v.Disallowed, pkg)
		}
	}
	return v
}

// mobileInbounds returns the inbounds for Android: the VPN's TUN, or the
// password-protected SOCKS5 proxy. There is never an open port in VPN mode.
func mobileInbounds(m Mobile, s Settings) ([]config.InboundConfig, error) {
	if s.Mode != "tun" {
		return []config.InboundConfig{{Tag: "socks", Type: "socks",
			Listen:   fmt.Sprintf("127.0.0.1:%d", s.ProxyPort),
			Username: s.ProxyUser, Password: s.ProxyPass}}, nil
	}
	vs, _ := json.Marshal(mobileVPN(s))
	fd, err := m.OpenTUN(string(vs))
	if err != nil {
		return nil, fmt.Errorf("VPN: %w", err)
	}
	if fd <= 0 {
		return nil, errors.New("VPN: no permission (allow nevio to create a VPN)")
	}
	return []config.InboundConfig{{Tag: "tun", Type: "tun", FD: fd, Address: mobileAddr4,
		Address6: mobileAddr6, MTU: mobileMTU}}, nil
}

// closeTUNFD closes a TUN descriptor that no client took over.
func closeTUNFD(in []config.InboundConfig) {
	for _, ic := range in {
		if ic.FD > 0 {
			os.NewFile(uintptr(ic.FD), "tun").Close()
		}
	}
}

// withoutProcessRules drops app rules from routing: on Android they are
// applied by the VPN itself (which apps it covers), not per connection.
func withoutProcessRules(rules []config.RuleConfig) []config.RuleConfig {
	out := rules[:0:0]
	for _, r := range rules {
		if len(r.Process) == 0 {
			out = append(out, r)
		}
	}
	return out
}

// mobileApps lists installed apps for the app picker.
func mobileApps(m Mobile) []procinfo.Process {
	var apps []struct {
		Name  string `json:"name"`
		Label string `json:"label"`
	}
	json.Unmarshal([]byte(m.Apps()), &apps)
	out := make([]procinfo.Process, 0, len(apps))
	for _, a := range apps {
		out = append(out, procinfo.Process{Name: a.Name, Label: a.Label})
	}
	return out
}

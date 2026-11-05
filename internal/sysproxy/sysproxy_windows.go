package sysproxy

import (
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const settingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

func notify() {
	internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	internetSetOption.Call(0, internetOptionRefresh, 0, 0)
}

// Saved is the user's previous proxy setting, restored by Restore.
type Saved struct {
	Enable   uint64
	Server   string
	Override string
}

// Enable points the Windows (WinINet) proxy at addr ("127.0.0.1:10809") and
// returns the previous setting.
func Enable(addr string) (*Saved, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	var prev Saved
	prev.Enable, _, _ = k.GetIntegerValue("ProxyEnable")
	prev.Server, _, _ = k.GetStringValue("ProxyServer")
	prev.Override, _, _ = k.GetStringValue("ProxyOverride")
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return nil, err
	}
	if err := k.SetStringValue("ProxyOverride", Bypass); err != nil {
		return nil, err
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return nil, err
	}
	notify()
	return &prev, nil
}

// Restore puts back a setting saved by Enable (or disables the proxy if nil).
func Restore(prev *Saved) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if prev == nil {
		prev = &Saved{}
	}
	k.SetStringValue("ProxyServer", prev.Server)
	k.SetStringValue("ProxyOverride", prev.Override)
	err = k.SetDWordValue("ProxyEnable", uint32(prev.Enable))
	notify()
	return err
}

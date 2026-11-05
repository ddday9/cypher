package main

import (
	"context"
	_ "embed"
	"log/slog"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"fyne.io/systray"
	"github.com/ddday9/cypher/internal/gui"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	//go:embed assets/tray_on.ico
	trayOn []byte
	//go:embed assets/tray_off.ico
	trayOff []byte
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procShowWindow    = user32.NewProc("ShowWindow")
	procSetForeground = user32.NewProc("SetForegroundWindow")
	procMessageBoxW   = user32.NewProc("MessageBoxW")
)

const (
	swRestore = 9
	mbIconErr = 0x10
)

func showError(msg string) {
	t, _ := windows.UTF16PtrFromString("cypher")
	m, _ := windows.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbIconErr)
}

func openBrowser(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

// window manages the single WebView2 window; closing it hides the app to
// the tray, and it is recreated on demand.
type window struct {
	mu   sync.Mutex
	w    webview2.WebView
	srv  *gui.Server
	data string
}

func (win *window) open() {
	win.mu.Lock()
	if win.w != nil {
		w := win.w
		win.mu.Unlock()
		w.Dispatch(func() {
			hwnd := uintptr(w.Window())
			procShowWindow.Call(hwnd, swRestore)
			procSetForeground.Call(hwnd)
		})
		return
	}
	go func() {
		runtime.LockOSThread()
		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			DataPath:  win.data,
			WindowOptions: webview2.WindowOptions{
				Title: "cypher", Width: 430, Height: 780, Center: true, IconId: 1,
			},
		})
		if w == nil {
			win.mu.Unlock()
			slog.Warn("WebView2 is not available, opening the browser")
			openBrowser(win.srv.URL())
			return
		}
		win.w = w
		win.mu.Unlock()
		w.Navigate(win.srv.URL())
		w.Run()
		win.mu.Lock()
		win.w = nil
		win.mu.Unlock()
		w.Destroy()
	}()
}

func (win *window) close() {
	win.mu.Lock()
	w := win.w
	win.mu.Unlock()
	if w != nil {
		w.Dispatch(w.Terminate)
	}
}

// setDPIAware keeps the window sharp on scaled displays even when the
// executable has no manifest (per-monitor v2, falling back to system aware).
func setDPIAware() {
	if p := user32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		const perMonitorV2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
		if r, _, _ := p.Call(perMonitorV2); r != 0 {
			return
		}
	}
	if p := user32.NewProc("SetProcessDPIAware"); p.Find() == nil {
		p.Call()
	}
}

func runUI(app *gui.App, srv *gui.Server, minimized, browser bool) {
	runtime.LockOSThread()
	setDPIAware()
	win := &window{srv: srv, data: gui.DataDir() + `\webview2`}
	show := win.open
	if browser {
		show = func() { openBrowser(srv.URL()) }
	}
	srv.OnShow = show
	srv.OnQuit = systray.Quit

	systray.Run(func() {
		systray.SetIcon(trayOff)
		systray.SetTooltip("cypher — не подключено")
		systray.SetOnTapped(show)
		mOpen := systray.AddMenuItem("Открыть cypher", "")
		mToggle := systray.AddMenuItem("Подключить", "")
		mTUN := systray.AddMenuItemCheckbox("Весь трафик (TUN)", "", app.Settings().Mode == "tun")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Выход", "")

		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					show()
				case <-mToggle.ClickedCh:
					go func() {
						if err := app.Toggle(context.Background()); err != nil {
							slog.Error("tray toggle", "err", err)
							show() // the window explains what went wrong
						}
					}()
				case <-mTUN.ClickedCh:
					mode := "tun"
					if mTUN.Checked() {
						mode = "proxy"
					}
					app.SetMode(mode)
					go app.Reconnect(context.Background())
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()
		go func() { // keep the tray in sync with the state
			last := -1
			for range time.Tick(time.Second) {
				on := 0
				if app.Connected() {
					on = 1
				}
				if app.Settings().Mode == "tun" {
					mTUN.Check()
				} else {
					mTUN.Uncheck()
				}
				if on == last {
					continue
				}
				last = on
				if on == 1 {
					systray.SetIcon(trayOn)
					systray.SetTooltip("cypher — подключено")
					mToggle.SetTitle("Отключить")
				} else {
					systray.SetIcon(trayOff)
					systray.SetTooltip("cypher — не подключено")
					mToggle.SetTitle("Подключить")
				}
			}
		}()
		if !minimized {
			show()
		}
	}, func() {
		win.close()
	})
}

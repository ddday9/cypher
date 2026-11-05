// Command cypher runs a cypher client or server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ddday9/cypher/internal/app"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/protocol"
)

var version = "dev"

const usage = `cypher — DPI-resistant proxy

Usage:
  cypher run -c config.json   run a client or server (decided by the config)
  cypher check -c config.json validate a config without starting
  cypher genkey               generate a user key
  cypher link -server example.com:443 -key KEY [-name NAME] [-sni NAME] [-fp firefox]
                              print a cypher:// link for the desktop client
  cypher version              print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run", "check":
		os.Exit(run(os.Args[1], os.Args[2:]))
	case "genkey":
		fmt.Println(protocol.GenerateKey().String())
	case "link":
		os.Exit(makeLink(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("cypher", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func run(cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	path := fs.String("c", "config.json", "path to the config file")
	fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	setupLogging(cfg.Log.Level)

	if cmd == "check" {
		if cfg.Server == nil {
			if _, err := app.NewClient(cfg); err != nil {
				fmt.Fprintln(os.Stderr, "config:", err)
				return 1
			}
		}
		fmt.Println("config OK")
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		slog.Error("fatal", "err", err)
		return 1
	}
	return 0
}

func makeLink(args []string) int {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	server := fs.String("server", "", "server host:port")
	key := fs.String("key", "", "user key")
	name := fs.String("name", "", "display name")
	sni := fs.String("sni", "", "TLS server name, if different from the host")
	fp := fs.String("fp", "", "fingerprint: firefox, chrome, safari, edge, ios, random")
	fs.Parse(args)
	if *server == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: cypher link -server HOST:PORT -key KEY [-name NAME]")
		return 2
	}
	if _, err := protocol.ParseKey(*key); err != nil {
		fmt.Fprintln(os.Stderr, "key:", err)
		return 1
	}
	fmt.Println(links.Format(links.Link{Name: *name, Server: *server, Key: *key, ServerName: *sni, Fingerprint: *fp}))
	return 0
}

func setupLogging(level string) {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

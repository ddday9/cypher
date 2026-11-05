package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ddday9/cypher/internal/app"
	"github.com/ddday9/cypher/internal/config"
	"github.com/ddday9/cypher/internal/links"
	"github.com/ddday9/cypher/internal/protocol"
)

const defaultServerConfig = "/etc/cypher/server.json"

// serve runs a server. If the config does not exist yet it is created from
// environment variables, so a container needs nothing but CYPHER_DOMAIN.
func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("c", envOr("CYPHER_CONFIG", defaultServerConfig), "server config file")
	fs.Parse(args)

	if _, err := os.Stat(*path); errors.Is(err, os.ErrNotExist) {
		if err := initServerConfig(*path); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if cfg.Server == nil {
		fmt.Fprintln(os.Stderr, "config:", *path, "has no \"server\" section")
		return 1
	}
	setupLogging(cfg.Log.Level)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		slog.Error("fatal", "err", err)
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func initServerConfig(path string) error {
	domain := strings.TrimSpace(os.Getenv("CYPHER_DOMAIN"))
	if domain == "" {
		return fmt.Errorf("%s does not exist; set CYPHER_DOMAIN (your domain pointing at this server) to create it", path)
	}
	key := protocol.GenerateKey().String()
	srv := &config.ServerConfig{
		Listen: envOr("CYPHER_LISTEN", ":443"),
		ACME: &config.ACMEConfig{
			Domain: domain, Email: os.Getenv("CYPHER_EMAIL"), CacheDir: "acme",
			DirectoryURL: os.Getenv("CYPHER_ACME_DIRECTORY"), CA: os.Getenv("CYPHER_ACME_CA"),
		},
		Users: []config.UserConfig{{Name: envOr("CYPHER_USER", "user1"), Key: key}},
	}
	// The site folder is checked on every request, so it may be filled later.
	srv.Fallback.Dir = envOr("CYPHER_SITE", "/var/www/cypher")
	cfg := config.Config{Server: srv}
	cfg.Log.Level = envOr("CYPHER_LOG", "info")
	if err := writeConfig(path, &cfg); err != nil {
		return err
	}
	fmt.Println("cypher: created", path)
	fmt.Println("cypher: link for the client (keep it secret):")
	fmt.Println(userLink(&cfg, srv.Users[0], ""))
	return nil
}

func writeConfig(path string, cfg *config.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// userLink builds a share link. host overrides the domain from the config;
// CYPHER_PUBLIC_PORT overrides the port (when Docker maps it differently).
func userLink(cfg *config.Config, u config.UserConfig, host string) string {
	if host == "" && cfg.Server.ACME != nil {
		host = cfg.Server.ACME.Domain
	}
	if host == "" {
		host = "YOUR-SERVER"
	}
	port := envOr("CYPHER_PUBLIC_PORT", "")
	if port == "" {
		_, port, _ = net.SplitHostPort(cfg.Server.Listen)
		if port == "" {
			port = "443"
		}
	}
	return links.Format(links.Link{Name: host + " · " + u.Name, Server: net.JoinHostPort(host, port), Key: u.Key})
}

func addUser(args []string) int {
	fs := flag.NewFlagSet("adduser", flag.ExitOnError)
	path := fs.String("c", envOr("CYPHER_CONFIG", defaultServerConfig), "server config file")
	name := fs.String("name", "", "user name")
	host := fs.String("host", "", "server address for the link (default: the ACME domain)")
	fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: cypher adduser -c FILE -name NAME")
		return 2
	}
	cfg, err := config.Load(*path)
	if err != nil || cfg.Server == nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	for _, u := range cfg.Server.Users {
		if u.Name == *name {
			fmt.Fprintf(os.Stderr, "user %q already exists\n", *name)
			return 1
		}
	}
	u := config.UserConfig{Name: *name, Key: protocol.GenerateKey().String()}
	cfg.Server.Users = append(cfg.Server.Users, u)
	if err := writeConfig(*path, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(userLink(cfg, u, *host))
	fmt.Fprintln(os.Stderr, "restart the server to apply (docker compose restart)")
	return 0
}

func printLinks(args []string) int {
	fs := flag.NewFlagSet("links", flag.ExitOnError)
	path := fs.String("c", envOr("CYPHER_CONFIG", defaultServerConfig), "server config file")
	host := fs.String("host", "", "server address for the links (default: the ACME domain)")
	fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil || cfg.Server == nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	for _, u := range cfg.Server.Users {
		fmt.Printf("%s\t%s\n", u.Name, userLink(cfg, u, *host))
	}
	return 0
}

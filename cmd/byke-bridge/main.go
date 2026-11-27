// byke-bridge runs byke bridge: a relay inside your network that lets byke's agents reach the services you name,
// without opening anything to the internet. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gitlab.com/byke-project/com.byke.bridge/relay"
)

var version = "dev"

func main() {
	server := flag.String("server", env("BYKE_BRIDGE_SERVER", "wss://bridge.byke.dev/v1/relay"), "byke's bridge gateway")
	token := flag.String("token", os.Getenv("BYKE_BRIDGE_TOKEN"), "the one-time enrollment token from the Bridges page (only the first start needs it)")
	state := flag.String("state", env("BYKE_BRIDGE_STATE", "/var/lib/byke-bridge"), "where the relay keeps its key and certificate")
	allow := flag.String("allow", os.Getenv("BYKE_BRIDGE_ALLOW"), "what it may reach, comma separated: host:port, *.suffix:port, CIDR:port (port * is any)")
	logFile := flag.String("log-file", os.Getenv("BYKE_BRIDGE_LOG_FILE"), "also write its log here (JSON lines)")
	flag.Parse()

	out := os.Stdout
	var handler slog.Handler = slog.NewJSONHandler(out, nil)
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "byke-bridge: its log file:", err)
			os.Exit(2)
		}
		handler = slog.NewJSONHandler(multi{out, f}, nil)
	}
	log := slog.New(handler).With("relay_version", version)

	var rules []string
	for _, a := range strings.Split(*allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			rules = append(rules, a)
		}
	}
	if len(rules) == 0 {
		log.Warn("its allow list is empty: it will refuse every connection (set --allow or BYKE_BRIDGE_ALLOW)")
	}
	r, err := relay.New(relay.Config{Server: *server, Token: *token, StateDir: *state, Allow: rules, Version: version, Log: log})
	if err != nil {
		fmt.Fprintln(os.Stderr, "byke-bridge:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := r.Run(ctx); err != nil {
		var refused relay.Refusal
		if errors.As(err, &refused) {
			fmt.Fprintln(os.Stderr, "byke-bridge:", err, "(enroll it again with a new token from the Bridges page)")
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "byke-bridge:", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type multi []*os.File

func (m multi) Write(p []byte) (int, error) {
	for _, f := range m {
		if _, err := f.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

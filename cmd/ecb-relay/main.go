// Command ecb-relay is the untrusted ecb relay server. Configuration is by
// environment only; see internal/relay.ConfigFromEnv.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
)

func main() {
	hc := flag.Bool("healthcheck", false, "probe http://127.0.0.1:<port from ECB_ADDR>/healthz and exit 0 (healthy) or 1")
	flag.Parse()
	if *hc {
		if err := healthcheck(os.Getenv("ECB_ADDR")); err != nil {
			fmt.Fprintln(os.Stderr, "ecb-relay: healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ecb-relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := relay.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := relay.New(cfg, log)
	if err != nil {
		return err
	}
	hs := srv.HTTPServer()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("relay listening", "addr", cfg.Addr, "max_item_bytes", cfg.MaxItemBytes, "item_ttl", cfg.ItemTTL.String())

	select {
	case err := <-errc:
		srv.Close()
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	srv.Close() // ends websockets and long-polls first
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// healthcheck GETs /healthz on the loopback interface at the port of addr
// (default :8080). It exists because the container image has no curl/wget.
func healthcheck(addr string) error {
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("bad ECB_ADDR %q", addr)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

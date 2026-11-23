// Command ecb-relay is the untrusted ecb relay server. Configuration is by
// environment only; see internal/relay.ConfigFromEnv.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
)

func main() {
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

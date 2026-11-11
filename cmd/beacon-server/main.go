package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	fs := flag.NewFlagSet("beacon-server", flag.ExitOnError)
	listen := fs.String("listen", envOr("BEACON_SERVER_LISTEN", "127.0.0.1:8080"), "listen address")
	vmURL := fs.String("vm-url", envOr("BEACON_VM_URL", "http://127.0.0.1:8428/api/v1/write"), "VictoriaMetrics remote-write URL")
	dataDir := fs.String("data-dir", envOr("BEACON_DATA_DIR", "/var/lib/beacon-server"), "state directory")
	enrollToken := fs.String("enroll-token", envOr("BEACON_ENROLL_TOKEN", ""), "one-time enrollment token")
	logLevel := fs.String("log-level", envOr("BEACON_LOG_LEVEL", "info"), "log level")
	_ = fs.Parse(os.Args[1:])

	var lv slog.Level
	switch *logLevel {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	if *enrollToken == "" {
		log.Warn("no enroll token configured: enrollment endpoint disabled, existing hosts still work")
	}

	store, err := OpenStore(filepath.Join(*dataDir, "hosts.json"))
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	events, err := OpenEvents(filepath.Join(*dataDir, "events.db"))
	if err != nil {
		log.Error("open events db", "err", err)
		os.Exit(1)
	}
	defer events.Close()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           NewServer(store, events, *vmURL, *enrollToken, log).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Persist last-seen timestamps periodically instead of on every write.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := store.Flush(); err != nil {
					log.Warn("flush store", "err", err)
				}
			}
		}
	}()

	go func() {
		log.Info("beacon-server listening", "addr", *listen, "vm", *vmURL, "data", *dataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	_ = store.Flush()
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

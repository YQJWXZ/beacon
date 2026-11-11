package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yqjwxz/beacon/internal/notify"
)

func main() {
	fs := flag.NewFlagSet("beacon-server", flag.ExitOnError)
	listen := fs.String("listen", envOr("BEACON_SERVER_LISTEN", "127.0.0.1:8080"), "listen address")
	vmURL := fs.String("vm-url", envOr("BEACON_VM_URL", "http://127.0.0.1:8428/api/v1/write"), "VictoriaMetrics remote-write URL")
	dataDir := fs.String("data-dir", envOr("BEACON_DATA_DIR", "/var/lib/beacon-server"), "state directory")
	enrollToken := fs.String("enroll-token", envOr("BEACON_ENROLL_TOKEN", ""), "one-time enrollment token")
	feishuWebhook := fs.String("feishu-webhook", envOr("BEACON_FEISHU_WEBHOOK", ""), "Feishu custom-bot webhook URL")
	feishuSecret := fs.String("feishu-secret", envOr("BEACON_FEISHU_SECRET", ""), "Feishu bot signing secret")
	amURL := fs.String("alertmanager-url", envOr("BEACON_ALERTMANAGER_URL", "http://alertmanager:9093"), "Alertmanager base URL")
	vmuiURL := fs.String("vmui-url", envOr("BEACON_VMUI_URL", "http://127.0.0.1:8428"), "VictoriaMetrics vmui base URL")
	webDir := fs.String("web-dir", envOr("BEACON_WEB_DIR", "web/dist"), "dashboard asset directory")
	publicURL := fs.String("public-url", envOr("BEACON_PUBLIC_URL", "http://127.0.0.1:8080"), "beacon-server URL reachable from a browser")
	eventsRetention := fs.Duration("events-retention", envDuration("BEACON_EVENTS_RETENTION", 90*24*time.Hour), "how long audit events are kept")
	snoozeSecret := fs.String("snooze-secret", envOr("BEACON_SNOOZE_SECRET", ""), "HMAC key for snooze links")
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

	snoozeKey := deriveSnoozeKey(*snoozeSecret, *enrollToken)
	var notifier *notify.Notifier
	if *feishuWebhook != "" {
		notifier = notify.NewNotifier(*feishuWebhook, *feishuSecret, *vmuiURL, *publicURL, snoozeKey)
		log.Info("feishu notifications enabled", "signed", *feishuSecret != "")
	} else {
		log.Warn("no feishu webhook configured: alert deliveries will return 503")
	}

	srv := &http.Server{
		Addr: *listen,
		Handler: NewServer(store, events, ServerOptions{
			VMURL:       *vmURL,
			VMBase:      strings.TrimSuffix(*vmURL, "/api/v1/write"),
			WebDir:      *webDir,
			EnrollToken: *enrollToken,
			AMURL:       *amURL,
			Notifier:    notifier,
			SnoozeKey:   snoozeKey,
		}, log).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Persist last-seen timestamps periodically instead of on every write.
	go pruneLoop(ctx, events, *eventsRetention, log)

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

// deriveSnoozeKey keeps the feature working with zero extra configuration:
// without an explicit secret the enrollment token is hashed into one. With
// neither set, snooze links are simply not generated.
func deriveSnoozeKey(secret, enrollToken string) []byte {
	if secret != "" {
		return []byte(secret)
	}
	if enrollToken != "" {
		sum := sha256.Sum256([]byte("beacon-snooze:" + enrollToken))
		return sum[:]
	}
	return nil
}

// pruneLoop trims the audit table on startup and every six hours. Without it
// the SQLite file grows forever, which is the one thing that degrades purely
// with time.
func pruneLoop(ctx context.Context, store *EventStore, retention time.Duration, log *slog.Logger) {
	if retention <= 0 {
		log.Info("event retention disabled")
		return
	}
	run := func() {
		cutoff := time.Now().Add(-retention)
		n, err := store.Prune(ctx, cutoff)
		if err != nil {
			log.Warn("prune events", "err", err)
			return
		}
		if n > 0 {
			log.Info("pruned events", "deleted", n, "older_than", cutoff.Format(time.RFC3339))
		}
		if n > 1000 {
			if err := store.Vacuum(ctx); err != nil {
				log.Warn("vacuum events", "err", err)
			}
		}
	}

	run()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

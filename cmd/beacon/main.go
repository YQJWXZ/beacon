package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/yqjwxz/beacon/internal/agent"
	"github.com/yqjwxz/beacon/internal/config"
	"github.com/yqjwxz/beacon/internal/version"
)

const usage = `beacon - host and network observability agent

Usage:
  beacon version
  beacon config check   [-config path]
  beacon agent run      [-config path] [-once] [-metrics-listen addr] [-log-level level]
  beacon agent check    [-config path]

Flags:
  -config         path to YAML config (default: none, built-in defaults)
  -once           collect once, print metrics to stdout and exit
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("beacon %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
	case "config":
		err = cmdConfig(os.Args[2:])
	case "agent":
		err = cmdAgent(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(level, format string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func loadConfig(path string, overrides map[string]*string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	for k, v := range overrides {
		if v == nil {
			continue
		}
		switch k {
		case "metrics-listen":
			cfg.Agent.Metrics.Listen = *v
		case "log-level":
			cfg.Log.Level = *v
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return fmt.Errorf("usage: beacon config check [-config path]")
	}
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Print(cfg.Redacted())
	for _, w := range cfg.Warnings() {
		fmt.Println("warning:", w)
	}
	fmt.Println("ok: configuration is valid")
	return nil
}

func cmdAgent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: beacon agent run|check")
	}
	switch args[0] {
	case "run":
		return cmdAgentRun(args[1:])
	case "check":
		return cmdAgentCheck(args[1:])
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}

func cmdAgentRun(args []string) error {
	fs := flag.NewFlagSet("agent run", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	once := fs.Bool("once", false, "collect once and print metrics to stdout")
	metricsListen := fs.String("metrics-listen", "", "override metrics listen address")
	logLevel := fs.String("log-level", "", "override log level")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ov := map[string]*string{}
	if *metricsListen != "" {
		ov["metrics-listen"] = metricsListen
	}
	if *logLevel != "" {
		ov["log-level"] = logLevel
	}
	cfg, err := loadConfig(*path, ov)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log.Level, cfg.Log.Format)
	a := agent.New(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := a.WriteMetrics(ctx, os.Stdout, 600*time.Millisecond); err != nil {
			return err
		}
		return nil
	}
	return a.Run(ctx)
}

func cmdAgentCheck(args []string) error {
	fs := flag.NewFlagSet("agent check", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path, nil)
	if err != nil {
		return err
	}
	log := newLogger("error", cfg.Log.Format)
	a := agent.New(cfg, log)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.Probe(ctx)

	fmt.Printf("host: %s\n", cfg.Agent.Host)
	if os.Geteuid() != 0 {
		fmt.Println("privileges: not root (firewall and process ownership checks will be limited)")
	} else {
		fmt.Println("privileges: root")
	}

	caps := a.Capabilities().Snapshot()
	keys := make([]string, 0, len(caps))
	for k := range caps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("capabilities:")
	for _, k := range keys {
		mark := "missing"
		if caps[k] {
			mark = "available"
		}
		fmt.Printf("  %-12s %s\n", k, mark)
	}

	if warns := cfg.Warnings(); len(warns) > 0 {
		fmt.Println("warnings:")
		for _, w := range warns {
			fmt.Println("  -", w)
		}
	}
	return nil
}

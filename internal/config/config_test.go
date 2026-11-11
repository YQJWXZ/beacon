package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Intervals.Fast.D() != 5*time.Second {
		t.Errorf("fast interval = %v", cfg.Agent.Intervals.Fast.D())
	}
	if cfg.Agent.Metrics.Listen != "127.0.0.1:9100" {
		t.Errorf("listen = %q", cfg.Agent.Metrics.Listen)
	}
	if cfg.Agent.Host == "" {
		t.Error("host identity must never be empty")
	}
}

func TestFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(p, []byte("agent:\n  intervals:\n    fast: 2s\n  metrics:\n    listen: 127.0.0.1:9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Intervals.Fast.D() != 2*time.Second {
		t.Errorf("fast = %v", cfg.Agent.Intervals.Fast.D())
	}
	if cfg.Agent.Intervals.Normal.D() != 15*time.Second {
		t.Errorf("normal should keep its default, got %v", cfg.Agent.Intervals.Normal.D())
	}
	if cfg.Agent.Metrics.Listen != "127.0.0.1:9999" {
		t.Errorf("listen = %q", cfg.Agent.Metrics.Listen)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	t.Setenv("BEACON_METRICS_LISTEN", "127.0.0.1:7777")
	t.Setenv("BEACON_LOG_LEVEL", "debug")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Metrics.Listen != "127.0.0.1:7777" || cfg.Log.Level != "debug" {
		t.Errorf("env not applied: %+v", cfg)
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"bad interval", func(c *Config) { c.Agent.Intervals.Fast = 0 }, "positive"},
		{"bad listen", func(c *Config) { c.Agent.Metrics.Listen = "nope" }, "metrics.listen"},
		{"bad dial", func(c *Config) { c.Transport.Dial = "carrier-pigeon" }, "transport.dial"},
		{"bad endpoint", func(c *Config) { c.Transport.Endpoint = "://x" }, "transport.endpoint"},
		{"bad log level", func(c *Config) { c.Log.Level = "verbose" }, "log.level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Agent.Host = "h"
			tc.mut(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRedactedHidesToken(t *testing.T) {
	cfg := Default()
	cfg.Agent.Host = "h"
	cfg.Transport.Token = "super-secret"
	out := cfg.Redacted()
	if strings.Contains(out, "super-secret") {
		t.Fatal("token leaked in redacted config")
	}
	if !strings.Contains(out, "***") {
		t.Fatal("token placeholder missing")
	}
}

func TestWarnings(t *testing.T) {
	cfg := Default()
	cfg.Agent.Host = "h"
	w := cfg.Warnings()
	if len(w) != 2 {
		t.Fatalf("want 2 warnings for empty endpoint/token, got %v", w)
	}
}

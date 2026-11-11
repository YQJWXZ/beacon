// Package config loads agent configuration with three layers of precedence:
// defaults < YAML file < environment variables < command line flags.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a YAML-friendly time.Duration ("5s", "1m").
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

type Config struct {
	Agent     Agent     `yaml:"agent"`
	Transport Transport `yaml:"transport"`
	Log       Log       `yaml:"log"`
}

type Agent struct {
	// Host overrides the detected host identity used as the "host" label.
	Host   string `yaml:"host"`
	ProcFS string `yaml:"procfs"`
	SysFS  string `yaml:"sysfs"`
	// MetadataProbe enables the one-shot cloud metadata reachability check.
	MetadataProbe bool `yaml:"metadata_probe"`
	// DiskMountExclude drops noisy mounts (container layers, cgroup, /run/*).
	DiskMountExclude string    `yaml:"disk_mount_exclude"`
	StateDir         string    `yaml:"state_dir"`
	Heartbeat        Duration  `yaml:"heartbeat"`
	WAL              WALConfig `yaml:"wal"`
	Intervals        Intervals `yaml:"intervals"`
	Metrics          Metrics   `yaml:"metrics"`
}

// WALConfig bounds the local store-and-forward buffer.
type WALConfig struct {
	MaxBytes     int64 `yaml:"max_bytes"`
	SegmentBytes int64 `yaml:"segment_bytes"`
}

// DefaultDiskMountExclude matches node_exporter's noise filter philosophy:
// container layers, credential bind mounts and /run/* are not capacity signals.
const DefaultDiskMountExclude = `^/(dev|proc|sys|run|var/lib/docker/.+|var/lib/containers/.+|snap/.+)($|/)`

type Intervals struct {
	Fast   Duration `yaml:"fast"`
	Normal Duration `yaml:"normal"`
	Slow   Duration `yaml:"slow"`
}

type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type Transport struct {
	Kind     string   `yaml:"kind"`
	Endpoint string   `yaml:"endpoint"`
	Dial     string   `yaml:"dial"`
	ProxyURL string   `yaml:"proxy_url"`
	Token    string   `yaml:"token"`
	Timeout  Duration `yaml:"timeout"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Default() *Config {
	return &Config{
		Agent: Agent{
			MetadataProbe:    true,
			DiskMountExclude: DefaultDiskMountExclude,
			StateDir:         "/var/lib/beacon",
			Heartbeat:        Duration(30 * time.Second),
			WAL:              WALConfig{MaxBytes: 64 << 20, SegmentBytes: 1 << 20},
			Intervals: Intervals{
				Fast:   Duration(5 * time.Second),
				Normal: Duration(15 * time.Second),
				Slow:   Duration(60 * time.Second),
			},
			Metrics: Metrics{Enabled: true, Listen: "127.0.0.1:9100"},
		},
		Transport: Transport{
			Kind:    "http",
			Dial:    "direct",
			Timeout: Duration(10 * time.Second),
		},
		Log: Log{Level: "info", Format: "text"},
	}
}

// Load reads the file if it exists, applies environment overrides and validates.
// An empty path is valid and yields defaults.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(b, cfg); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
		case os.IsNotExist(err):
			return nil, fmt.Errorf("config file not found: %s", path)
		default:
			return nil, err
		}
	}

	applyEnv(cfg)

	if cfg.Agent.Host == "" {
		cfg.Agent.Host = DetectHostID()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(c *Config) {
	set := func(env string, dst *string) {
		if v, ok := os.LookupEnv(env); ok {
			*dst = v
		}
	}
	set("BEACON_AGENT_HOST", &c.Agent.Host)
	set("BEACON_PROCFS", &c.Agent.ProcFS)
	set("BEACON_SYSFS", &c.Agent.SysFS)
	set("BEACON_STATE_DIR", &c.Agent.StateDir)
	set("BEACON_METRICS_LISTEN", &c.Agent.Metrics.Listen)
	set("BEACON_LOG_LEVEL", &c.Log.Level)
	set("BEACON_LOG_FORMAT", &c.Log.Format)
	set("BEACON_TRANSPORT_ENDPOINT", &c.Transport.Endpoint)
	set("BEACON_TRANSPORT_TOKEN", &c.Transport.Token)
	set("BEACON_TRANSPORT_DIAL", &c.Transport.Dial)
	set("BEACON_TRANSPORT_PROXY_URL", &c.Transport.ProxyURL)

	if v, ok := os.LookupEnv("BEACON_METRICS_ENABLED"); ok {
		c.Agent.Metrics.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
}

// DetectHostID returns a stable identity that survives IP changes.
func DetectHostID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func (c *Config) Validate() error {
	if c.Agent.Intervals.Fast.D() <= 0 || c.Agent.Intervals.Normal.D() <= 0 || c.Agent.Intervals.Slow.D() <= 0 {
		return fmt.Errorf("all intervals must be positive")
	}
	if c.Agent.Heartbeat.D() <= 0 {
		return fmt.Errorf("agent.heartbeat must be positive")
	}
	if c.Agent.WAL.MaxBytes <= 0 || c.Agent.WAL.SegmentBytes <= 0 {
		return fmt.Errorf("agent.wal sizes must be positive")
	}
	if c.Agent.WAL.MaxBytes < c.Agent.WAL.SegmentBytes {
		return fmt.Errorf("agent.wal.max_bytes must be >= segment_bytes")
	}
	if c.Agent.Metrics.Enabled {
		if _, _, err := net.SplitHostPort(c.Agent.Metrics.Listen); err != nil {
			return fmt.Errorf("invalid metrics.listen %q: %w", c.Agent.Metrics.Listen, err)
		}
	}
	switch c.Transport.Kind {
	case "http":
	default:
		return fmt.Errorf("unsupported transport.kind %q (want http)", c.Transport.Kind)
	}
	switch c.Transport.Dial {
	case "direct", "system", "tsnet", "proxy", "unix":
	default:
		return fmt.Errorf("unsupported transport.dial %q", c.Transport.Dial)
	}
	if c.Transport.Endpoint != "" {
		u, err := url.Parse(c.Transport.Endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid transport.endpoint %q", c.Transport.Endpoint)
		}
	}
	if c.Agent.DiskMountExclude != "" {
		if _, err := regexp.Compile(c.Agent.DiskMountExclude); err != nil {
			return fmt.Errorf("invalid agent.disk_mount_exclude: %w", err)
		}
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log.level %q", c.Log.Level)
	}
	return nil
}

// Redacted returns a YAML rendering safe for logs: tokens are masked.
func (c *Config) Redacted() string {
	cp := *c
	if cp.Transport.Token != "" {
		cp.Transport.Token = "***"
	}
	b, err := yaml.Marshal(&cp)
	if err != nil {
		return fmt.Sprintf("<unrenderable config: %v>", err)
	}
	return string(b)
}

// Warnings lists non-fatal misconfigurations worth surfacing at startup.
func (c *Config) Warnings() []string {
	var w []string
	if c.Transport.Endpoint == "" {
		w = append(w, "transport.endpoint is empty: agent will collect but cannot ship metrics")
	}
	if c.Transport.Token == "" {
		w = append(w, "transport.token is empty: the center will reject writes once enabled")
	}
	if c.Agent.Metrics.Listen != "" && !strings.HasPrefix(c.Agent.Metrics.Listen, "127.") &&
		!strings.HasPrefix(c.Agent.Metrics.Listen, "localhost") {
		w = append(w, "metrics.listen is not loopback: metrics endpoint is exposed to the network")
	}
	return w
}

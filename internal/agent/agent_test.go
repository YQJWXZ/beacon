package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yqjwxz/beacon/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Agent.Host = "testhost"
	cfg.Agent.ProcFS = "../../internal/collector/testdata/proc"
	cfg.Agent.SysFS = "../../internal/collector/testdata/sys"
	cfg.Agent.MetadataProbe = false
	cfg.Agent.Metrics.Enabled = false
	return cfg
}

func TestWriteMetricsExposition(t *testing.T) {
	cfg := testConfig(t)
	a, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	a.Probe(context.Background())

	var buf bytes.Buffer
	if err := a.WriteMetrics(context.Background(), &buf, 0); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"beacon_cpu_steal_ratio",
		"beacon_mem_used_ratio",
		"beacon_net_rx_bytes_total",
		"beacon_disk_used_ratio",
		"beacon_agent_up",
		"beacon_capability_available",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in exposition", want)
		}
	}
}

func TestMetricNamesFollowConvention(t *testing.T) {
	cfg := testConfig(t)
	a, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	a.Probe(context.Background())

	var buf bytes.Buffer
	if err := a.WriteMetrics(context.Background(), &buf, 0); err != nil {
		t.Fatal(err)
	}

	nameRE := regexp.MustCompile(`^beacon_[a-z0-9_]+$`)
	var series int
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series++
		name, _, _ := strings.Cut(line, "{")
		name, _, _ = strings.Cut(name, " ")
		if !nameRE.MatchString(name) {
			t.Fatalf("metric %q violates naming convention", name)
		}
	}
	if series == 0 {
		t.Fatal("no series emitted")
	}
	if series > 800 {
		t.Fatalf("series budget exceeded: %d > 800", series)
	}
}

func TestAgentWithAuditRegistersCleanly(t *testing.T) {
	cfg := testConfig(t)
	cfg.Audit.Enabled = true
	cfg.Agent.StateDir = t.TempDir()
	cfg.Audit.Interval = config.Duration(0)
	// Interval 0 is rejected by Validate; use a real one instead.
	cfg.Audit.Interval = config.Duration(60 * time.Second)

	a, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	a.Probe(context.Background())

	var buf bytes.Buffer
	if err := a.WriteMetrics(context.Background(), &buf, 0); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"beacon_fw_service_active",
		"beacon_fw_readable",
		"beacon_port_listen_info",
		"beacon_exposure_unexpected",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
}

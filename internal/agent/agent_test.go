package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"testing"

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
	a := New(cfg, discardLogger())
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
	a := New(cfg, discardLogger())
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

// Package capability probes optional host facilities once at startup.
// Missing capabilities must degrade gracefully, never abort the agent.
package capability

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/procfs"
)

// Names of probed capabilities. Keep this list sorted for stable output.
var Names = []string{
	"auditd", "conntrack", "iptables", "metadata", "nft", "psi", "smartctl", "ss",
}

type Set struct {
	mu     sync.RWMutex
	values map[string]bool
	host   string
}

func NewSet(host string) *Set {
	return &Set{values: map[string]bool{}, host: host}
}

func (s *Set) Get(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values[name]
}

func (s *Set) Snapshot() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

// Probe checks every capability. Network probes are bounded by timeout.
func (s *Set) Probe(ctx context.Context, src *procfs.Source, timeout time.Duration) {
	vals := map[string]bool{
		"nft":       hasBinary("nft"),
		"iptables":  hasBinary("iptables"),
		"ss":        hasBinary("ss"),
		"smartctl":  hasBinary("smartctl"),
		"auditd":    hasFile("/run/auditd.pid") || hasProcess("auditd"),
		"psi":       src.ExistsProc("pressure", "cpu"),
		"conntrack": src.ExistsProc("sys", "net", "netfilter", "nf_conntrack_count"),
	}
	vals["metadata"] = probeMetadata(ctx, timeout)

	s.mu.Lock()
	s.values = vals
	s.mu.Unlock()
}

func hasFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func hasProcess(name string) bool {
	return hasBinary("pgrep") && exec.Command("pgrep", "-x", name).Run() == nil
}

// probeMetadata performs a single short request to the cloud metadata service.
// Failure is normal on bare metal and must stay cheap.
func probeMetadata(ctx context.Context, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet,
		"http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK
}

// Report returns capability names in a stable order for CLI output.
func (s *Set) Report() []string {
	snap := s.Snapshot()
	out := make([]string, 0, len(snap))
	for k := range snap {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Exporter exposes the probe result as beacon_capability_available{name}.
type Exporter struct {
	set  *Set
	desc *prometheus.Desc
}

func NewExporter(set *Set) *Exporter {
	var cl prometheus.Labels
	if set.host != "" {
		cl = prometheus.Labels{"host": set.host}
	}
	return &Exporter{
		set: set,
		desc: prometheus.NewDesc("beacon_capability_available",
			"Optional host facility is available (1) or missing (0).", []string{"name"}, cl),
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) { ch <- e.desc }

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for name, ok := range e.set.Snapshot() {
		v := 0.0
		if ok {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(e.desc, prometheus.GaugeValue, v, name)
	}
}

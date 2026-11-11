package agent

import (
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Self exposes the agent's own health. Without it, a broken collector looks
// exactly like a healthy host.
type Self struct {
	mu      sync.RWMutex
	last    map[string]float64
	errors  map[string]uint64
	buffer  float64
	up      float64
	version string
	commit  string

	dUp       *prometheus.Desc
	dDuration *prometheus.Desc
	dErrors   *prometheus.Desc
	dBuffer   *prometheus.Desc
	dInfo     *prometheus.Desc
}

func NewSelf(host, version, commit string) *Self {
	var cl prometheus.Labels
	if host != "" {
		cl = prometheus.Labels{"host": host}
	}
	return &Self{
		up:      1,
		version: version,
		commit:  commit,
		last:    map[string]float64{},
		errors:  map[string]uint64{},
		dUp:     prometheus.NewDesc("beacon_agent_up", "Agent is running.", nil, cl),
		dDuration: prometheus.NewDesc("beacon_agent_collect_duration_seconds",
			"Duration of the last collection cycle.", []string{"collector"}, cl),
		dErrors: prometheus.NewDesc("beacon_agent_collect_errors_total",
			"Collection errors since start.", []string{"collector"}, cl),
		dBuffer: prometheus.NewDesc("beacon_agent_buffer_bytes",
			"Bytes buffered in the local WAL (0 before the shipper is enabled).", nil, cl),
		dInfo: prometheus.NewDesc("beacon_agent_build_info",
			"Build information.", []string{"version", "commit", "go"}, cl),
	}
}

func (s *Self) SetBufferBytes(n float64) {
	s.mu.Lock()
	s.buffer = n
	s.mu.Unlock()
}

// Observe records one collection cycle.
func (s *Self) Observe(name string, d time.Duration, err error) {
	s.mu.Lock()
	s.last[name] = d.Seconds()
	if err != nil {
		s.errors[name]++
	}
	s.mu.Unlock()
}

func (s *Self) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.dUp
	ch <- s.dDuration
	ch <- s.dErrors
	ch <- s.dBuffer
	ch <- s.dInfo
}

func (s *Self) Collect(ch chan<- prometheus.Metric) {
	s.mu.RLock()
	last := make(map[string]float64, len(s.last))
	for k, v := range s.last {
		last[k] = v
	}
	errs := make(map[string]uint64, len(s.errors))
	for k, v := range s.errors {
		errs[k] = v
	}
	buf := s.buffer
	s.mu.RUnlock()

	ch <- prometheus.MustNewConstMetric(s.dUp, prometheus.GaugeValue, s.up)
	for k, v := range last {
		ch <- prometheus.MustNewConstMetric(s.dDuration, prometheus.GaugeValue, v, k)
	}
	for k, v := range errs {
		ch <- prometheus.MustNewConstMetric(s.dErrors, prometheus.CounterValue, float64(v), k)
	}
	ch <- prometheus.MustNewConstMetric(s.dBuffer, prometheus.GaugeValue, buf)
	ch <- prometheus.MustNewConstMetric(s.dInfo, prometheus.GaugeValue, 1, s.version, s.commit, runtime.Version())
}

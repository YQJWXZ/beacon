package collector

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/audit"
	"github.com/yqjwxz/beacon/internal/flow"
	"github.com/yqjwxz/beacon/internal/procfs"
)

// FlowOptions bounds the flow collector's cost.
type FlowOptions struct {
	MaxEntries       int
	TopK             int
	EgressMultiplier float64
	BaselinePath     string
	Cooldown         time.Duration
}

// Flow samples the conntrack table, aggregates it into bounded dimensions and
// runs the rule-based detectors.
type Flow struct {
	base
	src      *procfs.Source
	interval time.Duration
	sink     audit.Sink
	opts     FlowOptions
	baseline *flow.Baseline

	mu       sync.RWMutex
	snap     *flow.Sample
	egress   float64
	expected float64
	samples  int
	findings []flow.Finding
	scores   map[string]scoredFinding
	lastEmit map[string]time.Time
	prevNet  map[string]netCounters
	prevAt   time.Time
	local    map[string]bool
	localAt  time.Time

	dConns, dUnreplied, dTotal         *prometheus.Desc
	dUniqueDst, dUniqueSrc, dLocalSkip *prometheus.Desc
	dPortConns, dTop                   *prometheus.Desc
	dEgress, dBaseline, dAnomaly       *prometheus.Desc
}

func NewFlow(src *procfs.Source, host string, interval time.Duration, sink audit.Sink, opts FlowOptions) *Flow {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 4096
	}
	if opts.TopK <= 0 {
		opts.TopK = 20
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = 10 * time.Minute
	}
	b := base{host: host}
	return &Flow{
		base: b, src: src, interval: interval, sink: sink, opts: opts,
		baseline:   flow.LoadBaseline(opts.BaselinePath),
		scores:     map[string]scoredFinding{},
		lastEmit:   map[string]time.Time{},
		dConns:     b.desc("beacon_flow_conns", "Connection table entries by direction.", "dir"),
		dUnreplied: b.desc("beacon_flow_unreplied", "Entries with no reply yet by direction.", "dir"),
		dTotal:     b.desc("beacon_flow_entries", "Total conntrack entries observed in the sample."),
		dUniqueDst: b.desc("beacon_flow_unique_dst_ports", "Distinct destination ports in this sample.", "dir"),
		dUniqueSrc: b.desc("beacon_flow_unique_sources_in", "Distinct inbound source addresses in this sample."),
		dLocalSkip: b.desc("beacon_flow_local_skipped", "Connections excluded because both ends are local."),
		dPortConns: b.desc("beacon_flow_dport_conns", "Connections per bounded destination-port bucket.", "dir", "port"),
		dTop:       b.desc("beacon_flow_top_destination_conns", "Busiest outbound destinations (top K).", "dst"),
		dEgress:    b.desc("beacon_flow_egress_bps", "Observed outbound bytes per second across non-loopback interfaces."),
		dBaseline:  b.desc("beacon_flow_egress_baseline_bps", "Learned egress baseline for this hour of week."),
		dAnomaly:   b.desc("beacon_flow_anomaly_score", "Last detector score by kind.", "kind"),
	}
}

func (f *Flow) Name() string            { return "flow" }
func (f *Flow) Interval() time.Duration { return f.interval }

func (f *Flow) Refresh(ctx context.Context) error {
	file, err := os.Open(f.src.ProcPath("net", "nf_conntrack"))
	if err != nil {
		return err
	}
	entries, _, err := flow.ReadConntrack(file, f.opts.MaxEntries)
	file.Close()
	if err != nil {
		return err
	}

	now := time.Now()
	local := f.localAddrs(now)
	sample := flow.Aggregate(entries, local, now)

	rate := f.egressRate(now)
	f.baseline.Observe(now, rate)
	expected := f.baseline.Expected(now)
	f.samples = f.baseline.Samples(now)

	// While warming up the model, write it back so a restart keeps learning.
	if f.samples%20 == 0 {
		_ = f.baseline.Save()
	}

	findings := flow.Detect(sample, flow.EgressContext{
		BPS: rate, Expected: expected, Samples: f.samples, Multiplier: f.opts.EgressMultiplier,
	})

	f.mu.Lock()
	f.snap = sample
	f.egress = rate
	f.expected = expected
	f.findings = findings
	f.rememberScores(findings, now)
	var events []audit.Event
	for _, finding := range findings {
		if last, ok := f.lastEmit[finding.Kind]; ok && now.Sub(last) < f.opts.Cooldown {
			continue
		}
		f.lastEmit[finding.Kind] = now
		events = append(events, audit.Event{
			Time: now, Host: f.host, Type: finding.Kind, Severity: finding.Severity,
			Data: finding.Evidence,
		})
	}
	f.mu.Unlock()

	for _, e := range events {
		f.sink.Emit(e)
	}
	return nil
}

// localAddrs caches interface addresses: they change rarely and enumerate
// slowly on hosts with many containers.
func (f *Flow) localAddrs(now time.Time) map[string]bool {
	if f.local != nil && now.Sub(f.localAt) < 5*time.Minute {
		return f.local
	}
	set := flow.LocalAddresses()
	f.local = set
	f.localAt = now
	return set
}

// egressRate sums non-loopback transmit counters and returns bytes/second.
func (f *Flow) egressRate(now time.Time) float64 {
	raw, err := f.src.ReadProc("net", "dev")
	if err != nil {
		return 0
	}
	cur := parseNetDev(raw)
	var total uint64
	for name, c := range cur {
		if name == "lo" {
			continue
		}
		total += c.TxBytes
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	prevAt := f.prevAt
	var prev uint64
	for name, c := range f.prevNet {
		if name == "lo" {
			continue
		}
		prev += c.TxBytes
	}
	f.prevNet = cur
	f.prevAt = now
	if prevAt.IsZero() || now.Sub(prevAt) <= 0 || total < prev {
		return 0
	}
	return float64(total-prev) / now.Sub(prevAt).Seconds()
}

func (f *Flow) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		f.dConns, f.dUnreplied, f.dTotal, f.dUniqueDst, f.dUniqueSrc,
		f.dPortConns, f.dTop, f.dEgress, f.dBaseline, f.dAnomaly, f.dLocalSkip,
	} {
		ch <- d
	}
}

func (f *Flow) Collect(ch chan<- prometheus.Metric) {
	f.mu.RLock()
	s := f.snap
	egress, expected := f.egress, f.expected
	findings := append([]flow.Finding(nil), f.findings...)
	scores := make(map[string]scoredFinding, len(f.scores))
	for k, v := range f.scores {
		scores[k] = v
	}
	f.mu.RUnlock()
	if s == nil {
		return
	}

	ch <- prometheus.MustNewConstMetric(f.dConns, prometheus.GaugeValue, float64(s.In.Conns), "in")
	ch <- prometheus.MustNewConstMetric(f.dConns, prometheus.GaugeValue, float64(s.Out.Conns), "out")
	ch <- prometheus.MustNewConstMetric(f.dUnreplied, prometheus.GaugeValue, float64(s.In.Unreplied), "in")
	ch <- prometheus.MustNewConstMetric(f.dUnreplied, prometheus.GaugeValue, float64(s.Out.Unreplied), "out")
	ch <- prometheus.MustNewConstMetric(f.dTotal, prometheus.GaugeValue, float64(s.Total))
	ch <- prometheus.MustNewConstMetric(f.dUniqueDst, prometheus.GaugeValue, float64(len(s.UniqueDstPortsIn)), "in")
	ch <- prometheus.MustNewConstMetric(f.dUniqueDst, prometheus.GaugeValue, float64(len(s.UniqueDstPortsOut)), "out")
	ch <- prometheus.MustNewConstMetric(f.dUniqueSrc, prometheus.GaugeValue, float64(len(s.UniqueSrcsIn)))
	ch <- prometheus.MustNewConstMetric(f.dLocalSkip, prometheus.GaugeValue, float64(s.LocalSkipped))

	for key, agg := range s.Ports {
		dir, port, ok := splitPortKey(key)
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(f.dPortConns, prometheus.GaugeValue, float64(agg.Conns), dir, port)
	}
	for _, d := range s.TopDestinations(f.opts.TopK) {
		ch <- prometheus.MustNewConstMetric(f.dTop, prometheus.GaugeValue, float64(d.Conns), d.Dst)
	}
	ch <- prometheus.MustNewConstMetric(f.dEgress, prometheus.GaugeValue, egress)
	ch <- prometheus.MustNewConstMetric(f.dBaseline, prometheus.GaugeValue, expected)
	_ = findings
	for kind, v := range scores {
		ch <- prometheus.MustNewConstMetric(f.dAnomaly, prometheus.GaugeValue, v.score, kind)
	}
}

func splitPortKey(key string) (string, string, bool) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}

// scoredFinding keeps a detector result visible for a short while after the
// sample that produced it, so a one-sample scan does not make an alert flap.
type scoredFinding struct {
	score float64
	at    time.Time
}

func (f *Flow) rememberScores(findings []flow.Finding, now time.Time) {
	const keep = 5 * time.Minute
	for k, v := range f.scores {
		if now.Sub(v.at) > keep {
			delete(f.scores, k)
		}
	}
	for _, finding := range findings {
		f.scores[finding.Kind] = scoredFinding{score: finding.Score, at: now}
	}
}

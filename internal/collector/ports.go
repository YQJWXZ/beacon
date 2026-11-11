package collector

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/audit"
)

// ExposureConfig describes the non-host sources of the exposure model.
type ExposureConfig struct {
	Allow        []string
	SG           []audit.SGEntry
	SGKnown      bool
	PublicIP     string
	ProbeTimeout time.Duration
}

// Ports snapshots listening sockets, diffs them and computes the exposure set.
type Ports struct {
	base
	run      audit.Runner
	interval time.Duration
	sink     audit.Sink
	state    string
	cfg      ExposureConfig
	allow    audit.Matcher

	mu       sync.RWMutex
	listens  []audit.Listen
	diff     audit.PortDiff
	exposure audit.Exposure
	loaded   bool
	changes  map[string]uint64

	dListen, dNew, dRemoved, dWidened                        *prometheus.Desc
	dPublic, dUnexpected, dSGUnknown, dProbeUnknown, dSGOpen *prometheus.Desc
}

func NewPorts(run audit.Runner, host string, interval time.Duration, sink audit.Sink, statePath string, cfg ExposureConfig) *Ports {
	b := base{host: host}
	return &Ports{
		base: b, run: run, interval: interval, sink: sink, state: statePath, cfg: cfg,
		allow:   audit.NewMatcher(cfg.Allow),
		changes: map[string]uint64{},
		dListen: b.desc("beacon_port_listen_info",
			"Listening socket (value is always 1).", "proto", "addr", "port", "comm", "uid"),
		dNew:          b.desc("beacon_port_new_total", "Newly observed listening sockets."),
		dRemoved:      b.desc("beacon_port_removed_total", "Listening sockets that disappeared."),
		dWidened:      b.desc("beacon_port_widened_total", "Listeners whose bind address became broader."),
		dPublic:       b.desc("beacon_port_public", "Listeners bound to all interfaces."),
		dUnexpected:   b.desc("beacon_exposure_unexpected", "Public listeners that are reachable and not allow-listed."),
		dSGUnknown:    b.desc("beacon_exposure_sg_unknown", "Security group source is unknown."),
		dProbeUnknown: b.desc("beacon_exposure_probe_unknown", "External reachability could not be probed."),
		dSGOpen:       b.desc("beacon_exposure_sg_open_no_listener", "Security group allows a port with no listener."),
	}
}

func (p *Ports) Name() string            { return "ports" }
func (p *Ports) Interval() time.Duration { return p.interval }

func (p *Ports) Refresh(ctx context.Context) error {
	listens, err := audit.CollectPorts(ctx, p.run)
	if err != nil {
		return err
	}

	p.mu.Lock()
	prev := p.listens
	if !p.loaded {
		prev = audit.LoadListensFile(p.state)
		p.loaded = true
	}
	diff := audit.DiffListens(prev, listens)
	if prev == nil {
		// First observation establishes the baseline; reporting every socket as
		// new on startup would train operators to ignore the alerts.
		diff = audit.PortDiff{}
	}

	reach := audit.ProbePorts(ctx, p.cfg.PublicIP, listens, p.cfg.ProbeTimeout)
	exposure := audit.Evaluate(audit.ExposureInput{
		Listen:    listens,
		SG:        p.cfg.SG,
		SGKnown:   p.cfg.SGKnown,
		Reachable: reach,
		Allow:     p.allow,
	})

	p.listens = listens
	p.diff = diff
	p.exposure = exposure

	var events []audit.Event
	for _, l := range diff.Added {
		p.changes["added"]++
		sev := "P1"
		if l.Public() {
			sev = "P0"
		}
		events = append(events, audit.Event{
			Time: time.Now(), Host: p.host, Type: "port_added", Severity: sev,
			Data: map[string]any{"listen": l, "allowed": p.allow.Allowed(l)},
		})
	}
	for _, l := range diff.Removed {
		p.changes["removed"]++
		events = append(events, audit.Event{
			Time: time.Now(), Host: p.host, Type: "port_removed", Severity: "P2",
			Data: map[string]any{"listen": l},
		})
	}
	for _, w := range diff.Widened {
		p.changes["widened"]++
		sev := "P1"
		if w.After.Public() {
			sev = "P0"
		}
		events = append(events, audit.Event{
			Time: time.Now(), Host: p.host, Type: "port_scope_widened", Severity: sev,
			Data: map[string]any{"before": w.Before, "after": w.After},
		})
	}
	if len(exposure.Unexpected) > 0 {
		p.changes["unexpected"]++
		events = append(events, audit.Event{
			Time: time.Now(), Host: p.host, Type: "exposure_unexpected", Severity: "P0",
			Data: map[string]any{"listeners": exposure.Unexpected, "security_group": "unknown"},
		})
	}
	p.mu.Unlock()

	if len(diff.Added)+len(diff.Removed)+len(diff.Widened) > 0 {
		_ = audit.SaveListensFile(p.state, listens)
	}
	for _, e := range events {
		p.sink.Emit(e)
	}
	return nil
}

func (p *Ports) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		p.dListen, p.dNew, p.dRemoved, p.dWidened,
		p.dPublic, p.dUnexpected, p.dSGUnknown, p.dProbeUnknown, p.dSGOpen,
	} {
		ch <- d
	}
}

func (p *Ports) Collect(ch chan<- prometheus.Metric) {
	p.mu.RLock()
	listens := p.listens
	exp := p.exposure
	changes := make(map[string]uint64, len(p.changes))
	for k, v := range p.changes {
		changes[k] = v
	}
	p.mu.RUnlock()
	if listens == nil {
		return
	}

	public := 0
	for _, l := range listens {
		if l.Public() {
			public++
		}
		ch <- prometheus.MustNewConstMetric(p.dListen, prometheus.GaugeValue, 1,
			l.Proto, l.Addr, strconv.Itoa(l.Port), l.Comm, strconv.Itoa(l.UID))
	}
	ch <- prometheus.MustNewConstMetric(p.dPublic, prometheus.GaugeValue, float64(public))
	for kind, v := range changes {
		var d *prometheus.Desc
		switch kind {
		case "added":
			d = p.dNew
		case "removed":
			d = p.dRemoved
		case "widened":
			d = p.dWidened
		default:
			continue
		}
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}
	ch <- prometheus.MustNewConstMetric(p.dUnexpected, prometheus.GaugeValue, float64(len(exp.Unexpected)))
	ch <- prometheus.MustNewConstMetric(p.dSGOpen, prometheus.GaugeValue, float64(len(exp.SGOpenNoListener)))
	ch <- prometheus.MustNewConstMetric(p.dSGUnknown, prometheus.GaugeValue, boolToFloat(exp.SGUnknown))
	ch <- prometheus.MustNewConstMetric(p.dProbeUnknown, prometheus.GaugeValue, boolToFloat(exp.ProbeUnknown))
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

package collector

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/audit"
)

// Firewall captures the host ruleset, detects changes and flags dangerous rules.
type Firewall struct {
	base
	run      audit.Runner
	interval time.Duration
	sink     audit.Sink
	state    string

	mu         sync.RWMutex
	snap       *audit.Snapshot
	active     bool
	risky      []audit.Rule
	open       []string
	lastChange time.Time
	changes    map[string]uint64
	loaded     bool

	dRules, dRisky, dOpen, dIPv6, dActive, dChanges, dLastChange *prometheus.Desc
}

func NewFirewall(run audit.Runner, host string, interval time.Duration, sink audit.Sink, statePath string) *Firewall {
	b := base{host: host}
	return &Firewall{
		base: b, run: run, interval: interval, sink: sink, state: statePath,
		changes:     map[string]uint64{},
		dRules:      b.desc("beacon_fw_rules_total", "Firewall rules per table.", "table"),
		dRisky:      b.desc("beacon_fw_risky_rules", "Accepted rules exposing a dangerous port to the whole internet."),
		dOpen:       b.desc("beacon_fw_policy_open", "Input chain whose default policy accepts (1=open).", "chain"),
		dIPv6:       b.desc("beacon_fw_ipv6_covered", "IPv6 traffic is filtered by the ruleset."),
		dActive:     b.desc("beacon_fw_service_active", "A firewall backend is active."),
		dChanges:    b.desc("beacon_fw_change_total", "Ruleset change events by kind.", "kind"),
		dLastChange: b.desc("beacon_fw_last_change_timestamp", "Unix time of the last detected ruleset change."),
	}
}

func (f *Firewall) Name() string            { return "firewall" }
func (f *Firewall) Interval() time.Duration { return f.interval }

func (f *Firewall) Refresh(ctx context.Context) error {
	snap, active, err := audit.CollectFirewall(ctx, f.run)
	if err != nil {
		return err
	}

	f.mu.Lock()
	prev := f.snap
	if !f.loaded {
		prev = audit.LoadSnapshotFile(f.state)
		f.loaded = true
	}
	f.snap = snap
	f.active = active
	f.risky = audit.RiskyRules(snap)
	f.open = audit.OpenPolicies(snap)

	var emitted []audit.Event
	if prev != nil && prev.Hash != "" && snap.Hash != prev.Hash {
		d := audit.DiffSnapshots(prev, snap)
		if !d.Empty() || d.Flushed {
			f.lastChange = time.Now()
			f.changes["total"]++
			severity := "P1"
			if d.Flushed {
				f.changes["flush"]++
				severity = "P0"
			}
			for _, pc := range d.PolicyChanges {
				f.changes["policy"]++
				if isOpenPolicy(pc.After) {
					severity = "P0"
				}
			}
			if len(d.Added) > 0 {
				f.changes["added"]++
			}
			if len(d.Removed) > 0 {
				f.changes["removed"]++
			}
			emitted = append(emitted, audit.Event{
				Time:     time.Now(),
				Host:     f.host,
				Type:     "fw_change",
				Severity: severity,
				Data: map[string]any{
					"backend":        string(snap.Backend),
					"before_hash":    d.BeforeHash,
					"after_hash":     d.AfterHash,
					"added":          d.Added,
					"removed":        d.Removed,
					"policy_changes": d.PolicyChanges,
					"flushed":        d.Flushed,
				},
			})
		}
	}
	f.mu.Unlock()

	if prev == nil || prev.Hash != snap.Hash {
		_ = audit.SaveSnapshotFile(f.state, snap)
	}
	for _, e := range emitted {
		f.sink.Emit(e)
	}
	return nil
}

func isOpenPolicy(p string) bool {
	return p == "accept" || p == "allow"
}

func (f *Firewall) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{f.dRules, f.dRisky, f.dOpen, f.dIPv6, f.dActive, f.dChanges, f.dLastChange} {
		ch <- d
	}
}

func (f *Firewall) Collect(ch chan<- prometheus.Metric) {
	f.mu.RLock()
	snap := f.snap
	risky := f.risky
	open := f.open
	active := f.active
	last := f.lastChange
	changes := make(map[string]uint64, len(f.changes))
	for k, v := range f.changes {
		changes[k] = v
	}
	f.mu.RUnlock()
	if snap == nil {
		return
	}

	for table, n := range snap.CountByTable() {
		ch <- prometheus.MustNewConstMetric(f.dRules, prometheus.GaugeValue, float64(n), table)
	}
	ch <- prometheus.MustNewConstMetric(f.dRisky, prometheus.GaugeValue, float64(len(risky)))
	for _, chain := range open {
		ch <- prometheus.MustNewConstMetric(f.dOpen, prometheus.GaugeValue, 1, chain)
	}
	ipv6 := 0.0
	if snap.IPv6Covered {
		ipv6 = 1
	}
	ch <- prometheus.MustNewConstMetric(f.dIPv6, prometheus.GaugeValue, ipv6)
	act := 0.0
	if active {
		act = 1
	}
	ch <- prometheus.MustNewConstMetric(f.dActive, prometheus.GaugeValue, act)
	for kind, v := range changes {
		ch <- prometheus.MustNewConstMetric(f.dChanges, prometheus.CounterValue, float64(v), kind)
	}
	ch <- prometheus.MustNewConstMetric(f.dLastChange, prometheus.GaugeValue, float64(last.Unix()))
}

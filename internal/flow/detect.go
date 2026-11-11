package flow

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Baseline is a per-hour-of-week EWMA of egress bandwidth. It is deliberately
// simple: an approximate "what is normal for this hour" beats a static
// threshold, and M5 upgrades it to quantiles over a 7-day window.
type Baseline struct {
	mu     sync.Mutex
	path   string
	Slots  [168]float64 `json:"slots"`
	Counts [168]int     `json:"counts"`
	dirty  int
}

func LoadBaseline(path string) *Baseline {
	b := &Baseline{path: path}
	if path == "" {
		return b
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return b
	}
	_ = json.Unmarshal(data, b)
	return b
}

func slotOf(t time.Time) int {
	return int(t.Weekday())*24 + t.Hour()
}

// Expected returns the learned rate for this hour of week.
func (b *Baseline) Expected(t time.Time) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Slots[slotOf(t)]
}

// Samples returns how many observations this slot has seen.
func (b *Baseline) Samples(t time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Counts[slotOf(t)]
}

// Observe folds one rate into the slot. Alpha shrinks after warmup so a single
// spike does not become the new normal.
func (b *Baseline) Observe(t time.Time, v float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := slotOf(t)
	alpha := 0.2
	if b.Counts[i] > 20 {
		alpha = 0.05
	}
	if b.Counts[i] == 0 {
		b.Slots[i] = v
	} else {
		b.Slots[i] = (1-alpha)*b.Slots[i] + alpha*v
	}
	b.Counts[i]++
	b.dirty++
}

// Save persists the model; callers should batch this, not run it per sample.
func (b *Baseline) Save() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path == "" || b.dirty == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		return err
	}
	b.dirty = 0
	return nil
}

// EgressContext carries the current rate and what the model expects.
type EgressContext struct {
	BPS        float64
	Expected   float64
	Samples    int
	Multiplier float64
}

// Anomalous reports whether the rate is far above the learned baseline. It
// requires warmup and an absolute floor so an idle host does not alert on
// 20 KB/s of background traffic.
func (c EgressContext) Anomalous() bool {
	if c.Samples < 3 || c.Expected <= 0 || c.Multiplier <= 0 {
		return false
	}
	floor := math.Max(c.Expected*c.Multiplier, c.Expected+1<<20)
	return c.BPS > floor
}

// Finding is one detector hit, ready to become an event.
type Finding struct {
	Kind     string         `json:"kind"`
	Severity string         `json:"severity"`
	Score    float64        `json:"score"`
	Evidence map[string]any `json:"evidence"`
}

// suspiciousDsts are outbound ports that essentially never belong to a healthy
// server. Redis/Mongo/Docker are included because outbound access to them is a
// classic lateral-movement and cryptomining pattern.
var suspiciousDsts = map[int]string{
	3333: "mining", 4444: "mining", 5555: "mining", 7777: "mining",
	9999: "mining", 14444: "mining", 6666: "malware", 6667: "irc-botnet",
	1080: "socks-proxy", 9050: "tor", 2375: "docker-api",
	6379: "redis", 9200: "elasticsearch", 27017: "mongodb",
}

// Detect runs the rule layer. Everything here is explainable from the sample;
// no detector depends on history except egress burst.
func Detect(s *Sample, egress EgressContext) []Finding {
	var out []Finding

	// Inbound port scan: many distinct destination ports, mostly unanswered.
	if len(s.UniqueDstPortsIn) >= 20 && s.In.Unreplied*2 >= s.In.Conns && s.In.Conns > 0 {
		out = append(out, Finding{
			Kind: "port_scan_in", Severity: "P1",
			Score: float64(len(s.UniqueDstPortsIn)),
			Evidence: map[string]any{
				"unique_dst_ports": len(s.UniqueDstPortsIn),
				"unreplied_ratio":  float64(s.In.Unreplied) / float64(s.In.Conns),
				"sample_ports":     sortedPorts(s.UniqueDstPortsIn, 10),
				"unique_sources":   len(s.UniqueSrcsIn),
			},
		})
	}

	// Outbound scan: a compromised host probing its neighbours.
	if len(s.UniqueDstPortsOut) >= 30 {
		out = append(out, Finding{
			Kind: "port_scan_out", Severity: "P0",
			Score: float64(len(s.UniqueDstPortsOut)),
			Evidence: map[string]any{
				"unique_dst_ports": len(s.UniqueDstPortsOut),
				"sample_ports":     sortedPorts(s.UniqueDstPortsOut, 10),
				"top_destinations": s.TopDestinations(5),
			},
		})
	}

	// SSH/RDP brute force: unanswered inbound connections to the admin port.
	for _, port := range []string{"22", "3389"} {
		agg := s.Ports["in|"+port]
		if agg.Unreplied >= 20 {
			out = append(out, Finding{
				Kind: "ssh_bruteforce", Severity: "P0",
				Score: float64(agg.Unreplied),
				Evidence: map[string]any{
					"port":           port,
					"unreplied":      agg.Unreplied,
					"unique_sources": len(s.UniqueSrcsIn),
				},
			})
			break
		}
	}

	// Outbound traffic to ports that should not be in a server's diet.
	for port, n := range s.SuspiciousOut {
		out = append(out, Finding{
			Kind: "suspicious_dport", Severity: "P0",
			Score: float64(n),
			Evidence: map[string]any{
				"dport": port, "category": suspiciousDsts[port],
				"connections": n, "top_destinations": s.TopDestinations(5),
			},
		})
		break // one finding per sample is enough; evidence names the rest
	}

	if egress.Anomalous() {
		out = append(out, Finding{
			Kind: "egress_burst", Severity: "P1",
			Score: egress.BPS / egress.Expected,
			Evidence: map[string]any{
				"observed_bps": egress.BPS,
				"baseline_bps": egress.Expected,
				"multiplier":   egress.Multiplier,
			},
		})
	}
	return out
}

func sortedPorts(set map[int]struct{}, limit int) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

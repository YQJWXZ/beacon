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

// Baseline learns "what is normal for this hour of week" from recent samples.
//
// Each of the 168 slots keeps a small ring of observations. Scoring uses P95
// and MAD rather than a mean, so a single spike neither becomes the new normal
// (as an EWMA would) nor hides behind it. The ring is capped so memory and the
// persisted file stay bounded no matter how long the agent runs.
type Baseline struct {
	mu    sync.Mutex
	path  string
	Model model `json:"model"`
	dirty int
}

type model struct {
	Version int       `json:"version"`
	Slots   [168]slot `json:"slots"`
}

type slot struct {
	Values []float64 `json:"v,omitempty"`
	Count  int       `json:"n"`
}

const (
	baselineVersion = 2
	ringSize        = 96
	// minSamples avoids scoring from a nearly empty slot.
	minSamples = 20
	// floorBytes keeps an idle host from alerting on background noise.
	floorBytes = 64 << 10
)

func LoadBaseline(path string) *Baseline {
	b := &Baseline{path: path}
	if path == "" {
		return b
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return b
	}
	var m model
	if err := json.Unmarshal(data, &m); err != nil || m.Version != baselineVersion {
		return b
	}
	b.Model = m
	return b
}

func slotOf(t time.Time) int { return int(t.Weekday())*24 + t.Hour() }

// Observe adds one rate sample to its slot.
func (b *Baseline) Observe(t time.Time, v float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := slotOf(t)
	s := &b.Model.Slots[i]
	s.Count++
	if len(s.Values) < ringSize {
		s.Values = append(s.Values, v)
	} else {
		copy(s.Values, s.Values[1:])
		s.Values[len(s.Values)-1] = v
	}
	b.Model.Version = baselineVersion
	b.dirty++
}

// Stats returns P50, P95 and MAD for the slot. n is the lifetime sample count;
// the statistics come from at most the last ringSize values.
func (b *Baseline) Stats(t time.Time) (p50, p95, mad float64, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.Model.Slots[slotOf(t)]
	p, q, m := stats(s.Values)
	return p, q, m, s.Count
}

func stats(values []float64) (p50, p95, mad float64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	p50 = quantile(sorted, 0.50)
	p95 = quantile(sorted, 0.95)

	dev := make([]float64, len(sorted))
	for i, v := range sorted {
		dev[i] = math.Abs(v - p50)
	}
	sort.Float64s(dev)
	mad = quantile(dev, 0.50)
	return p50, p95, mad
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

// Score expresses how far above normal a rate is. It returns 0 when the slot
// is still cold or the rate is within the learned range.
func (b *Baseline) Score(t time.Time, v float64) (score, p95 float64, n int) {
	p50, p95v, mad, count := b.Stats(t)
	if count < minSamples {
		return 0, p95v, count
	}
	// MAD can be zero on a very stable link; fall back to a relative floor so
	// small absolute noise does not explode the score.
	denom := math.Max(1.4826*mad, math.Max(0.05*p95v, 1024))
	if v <= p95v {
		return 0, p95v, count
	}
	_ = p50
	return (v - p95v) / denom, p95v, count
}

// Save persists the model. Callers should batch this, not run it per sample.
func (b *Baseline) Save() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path == "" || b.dirty == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b.Model)
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

// EgressContext carries the current rate and the model's verdict.
type EgressContext struct {
	BPS      float64
	P95      float64
	Score    float64
	Samples  int
	Streak   int
	MinScore float64
}

// Anomalous reports whether the current sample should raise a finding.
func (c EgressContext) Anomalous() bool {
	if c.Samples < minSamples || c.BPS < floorBytes {
		return false
	}
	lim := c.MinScore
	if lim <= 0 {
		lim = 3
	}
	return c.Score > lim && c.Streak >= 3
}

package notify

import (
	"sync"
	"time"
)

// deduper suppresses repeated cards for the same alert group and caps the
// global send rate. Alertmanager already groups and repeats; this is the last
// line of defence against a rule that flaps.
type deduper struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time

	limit  int
	tokens float64
	lastAt time.Time
}

func newDeduper(window time.Duration, perMinute int) *deduper {
	return &deduper{
		window: window,
		last:   map[string]time.Time{},
		limit:  perMinute,
		tokens: float64(perMinute),
		lastAt: time.Now(),
	}
}

// seen returns true when the group was already delivered inside the window or
// the global rate limit is exhausted.
func (d *deduper) seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if !d.allowLocked(now) {
		return true
	}
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		return true
	}
	d.last[key] = now
	if len(d.last) > 1000 {
		for k, t := range d.last {
			if now.Sub(t) > d.window {
				delete(d.last, k)
			}
		}
	}
	return false
}

func (d *deduper) allowLocked(now time.Time) bool {
	elapsed := now.Sub(d.lastAt).Seconds()
	d.tokens += elapsed * float64(d.limit) / 60
	if d.tokens > float64(d.limit) {
		d.tokens = float64(d.limit)
	}
	d.lastAt = now
	if d.tokens < 1 {
		return false
	}
	d.tokens--
	return true
}

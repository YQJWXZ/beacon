package collector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/procfs"
)

// Collector is a snapshot producer scheduled by the agent and exposed as
// Prometheus metrics. Refresh must be cheap: it runs on a fixed cadence, while
// Collect only reads the last snapshot and must never block on I/O.
type Collector interface {
	Name() string
	Interval() time.Duration
	Refresh(ctx context.Context) error
	prometheus.Collector
}

type base struct {
	host string
}

func (b base) desc(name, help string, labels ...string) *prometheus.Desc {
	var cl prometheus.Labels
	if b.host != "" {
		cl = prometheus.Labels{"host": b.host}
	}
	return prometheus.NewDesc(name, help, labels, cl)
}

func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func ratio(num, den uint64) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func f64(b []byte) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
}

// cpuTimes is the first line of /proc/stat in jiffies.
type cpuTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

func (t cpuTimes) total() uint64 {
	return t.User + t.Nice + t.System + t.Idle + t.IOWait + t.IRQ + t.SoftIRQ + t.Steal
}

type cpuScalars struct {
	Ctxt         uint64
	Processes    uint64
	ProcsRunning uint64
	ProcsBlocked uint64
}

func parseProcStat(b []byte) (cpuTimes, cpuScalars, error) {
	var t cpuTimes
	var s cpuScalars
	var haveCPU bool
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "cpu":
			haveCPU = true
			// user nice system idle iowait irq softirq steal [guest guest_nice]
			vals := make([]uint64, 8)
			for i := 0; i < 8 && i+1 < len(fields); i++ {
				v, err := strconv.ParseUint(fields[i+1], 10, 64)
				if err != nil {
					return t, s, fmt.Errorf("parse cpu field %d: %w", i, err)
				}
				vals[i] = v
			}
			t = cpuTimes{
				User: vals[0], Nice: vals[1], System: vals[2], Idle: vals[3],
				IOWait: vals[4], IRQ: vals[5], SoftIRQ: vals[6], Steal: vals[7],
			}
		case "ctxt":
			if len(fields) > 1 {
				s.Ctxt, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		case "processes":
			if len(fields) > 1 {
				s.Processes, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		case "procs_running":
			if len(fields) > 1 {
				s.ProcsRunning, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		case "procs_blocked":
			if len(fields) > 1 {
				s.ProcsBlocked, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	if !haveCPU {
		return t, s, fmt.Errorf("no cpu line in /proc/stat")
	}
	return t, s, nil
}

func parseLoadavg(b []byte) (l1, l5, l15 float64, err error) {
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("short /proc/loadavg")
	}
	if l1, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, err
	}
	if l5, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, err
	}
	l15, err = strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15, err
}

// parsePSI returns avg10/avg60/avg300 for the "some" and "full" lines.
func parsePSI(b []byte) (some, full map[string]float64) {
	some = map[string]float64{}
	full = map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var target map[string]float64
		switch fields[0] {
		case "some":
			target = some
		case "full":
			target = full
		default:
			continue
		}
		for _, kv := range fields[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			target[k] = n
		}
	}
	return some, full
}

type cpuSnapshot struct {
	usage   map[string]float64
	steal   float64
	load1   float64
	load5   float64
	load15  float64
	running uint64
	blocked uint64
	ctxt    uint64
	psiSome float64
	psiFull float64
	hasPSI  bool
	hasLoad bool
}

type CPU struct {
	base
	src      *procfs.Source
	interval time.Duration

	mu   sync.RWMutex
	prev *cpuTimes
	snap *cpuSnapshot

	descUsage *prometheus.Desc
	descSteal *prometheus.Desc
	descLoad  *prometheus.Desc
	descProcs *prometheus.Desc
	descCtxt  *prometheus.Desc
	descPSI   *prometheus.Desc
}

func NewCPU(src *procfs.Source, host string, interval time.Duration) *CPU {
	b := base{host: host}
	return &CPU{
		base:     b,
		src:      src,
		interval: interval,
		descUsage: b.desc("beacon_cpu_usage_ratio",
			"CPU time share per mode over the last refresh interval.", "mode"),
		descSteal: b.desc("beacon_cpu_steal_ratio",
			"CPU time stolen by the hypervisor; the key signal on cloud instances."),
		descLoad: b.desc("beacon_load",
			"System load average.", "window"),
		descProcs: b.desc("beacon_procs",
			"Processes in a runnable or uninterruptible state.", "state"),
		descCtxt: b.desc("beacon_ctx_switches_total",
			"Context switches since boot."),
		descPSI: b.desc("beacon_psi_cpu_avg10",
			"CPU pressure stall information, 10 second average (percent).", "kind"),
	}
}

func (c *CPU) Name() string            { return "cpu" }
func (c *CPU) Interval() time.Duration { return c.interval }

func (c *CPU) Refresh(ctx context.Context) error {
	raw, err := c.src.ReadProc("stat")
	if err != nil {
		return err
	}
	cur, scalars, err := parseProcStat(raw)
	if err != nil {
		return err
	}

	snap := &cpuSnapshot{ctxt: scalars.Ctxt, running: scalars.ProcsRunning, blocked: scalars.ProcsBlocked}

	if lb, err := c.src.ReadProc("loadavg"); err == nil {
		if l1, l5, l15, err := parseLoadavg(lb); err == nil {
			snap.load1, snap.load5, snap.load15, snap.hasLoad = l1, l5, l15, true
		}
	}

	if pb, err := c.src.ReadProc("pressure", "cpu"); err == nil {
		some, full := parsePSI(pb)
		snap.psiSome, snap.psiFull, snap.hasPSI = some["avg10"], full["avg10"], true
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.prev == nil {
		// First sample: no interval to compute rates over. Keep gauges only.
		c.prev = &cur
		c.snap = snap
		return nil
	}

	prev := *c.prev
	dTotal := delta(cur.total(), prev.total())
	if dTotal > 0 {
		snap.usage = map[string]float64{
			"user":    ratio(delta(cur.User, prev.User), dTotal),
			"nice":    ratio(delta(cur.Nice, prev.Nice), dTotal),
			"system":  ratio(delta(cur.System, prev.System), dTotal),
			"idle":    ratio(delta(cur.Idle, prev.Idle), dTotal),
			"iowait":  ratio(delta(cur.IOWait, prev.IOWait), dTotal),
			"irq":     ratio(delta(cur.IRQ, prev.IRQ), dTotal),
			"softirq": ratio(delta(cur.SoftIRQ, prev.SoftIRQ), dTotal),
			"steal":   ratio(delta(cur.Steal, prev.Steal), dTotal),
		}
		snap.steal = snap.usage["steal"]
	}
	c.prev = &cur
	c.snap = snap
	return nil
}

var cpuModes = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

func (c *CPU) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descUsage
	ch <- c.descSteal
	ch <- c.descLoad
	ch <- c.descProcs
	ch <- c.descCtxt
	ch <- c.descPSI
}

func (c *CPU) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snap := c.snap
	c.mu.RUnlock()
	if snap == nil {
		return
	}
	for _, m := range cpuModes {
		if v, ok := snap.usage[m]; ok {
			ch <- prometheus.MustNewConstMetric(c.descUsage, prometheus.GaugeValue, v, m)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.descSteal, prometheus.GaugeValue, snap.steal)
	if snap.hasLoad {
		ch <- prometheus.MustNewConstMetric(c.descLoad, prometheus.GaugeValue, snap.load1, "1m")
		ch <- prometheus.MustNewConstMetric(c.descLoad, prometheus.GaugeValue, snap.load5, "5m")
		ch <- prometheus.MustNewConstMetric(c.descLoad, prometheus.GaugeValue, snap.load15, "15m")
	}
	ch <- prometheus.MustNewConstMetric(c.descProcs, prometheus.GaugeValue, float64(snap.running), "running")
	ch <- prometheus.MustNewConstMetric(c.descProcs, prometheus.GaugeValue, float64(snap.blocked), "blocked")
	ch <- prometheus.MustNewConstMetric(c.descCtxt, prometheus.CounterValue, float64(snap.ctxt))
	if snap.hasPSI {
		ch <- prometheus.MustNewConstMetric(c.descPSI, prometheus.GaugeValue, snap.psiSome, "some")
		ch <- prometheus.MustNewConstMetric(c.descPSI, prometheus.GaugeValue, snap.psiFull, "full")
	}
}

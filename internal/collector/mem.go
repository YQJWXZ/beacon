package collector

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yqjwxz/beacon/internal/procfs"
)

// parseMeminfo returns byte values keyed by the field name without the colon.
func parseMeminfo(b []byte) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v *= 1024
		}
		out[strings.TrimSpace(key)] = v
	}
	return out
}

// parseVMStat returns numeric /proc/vmstat counters.
func parseVMStat(b []byte) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		out[fields[0]] = v
	}
	return out
}

type memSnapshot struct {
	total, available, used float64
	usedRatio              float64
	cached, buffers, slab  float64
	shmem                  float64
	swapRatio              float64
	swapIn, swapOut        float64
	oomKill                float64
	dirty, writeback       float64
	psiSome, psiFull       float64
	hasPSI                 bool
}

type Mem struct {
	base
	src      *procfs.Source
	interval time.Duration
	pageSize float64

	mu   sync.RWMutex
	snap *memSnapshot

	dTotal, dUsed, dRatio  *prometheus.Desc
	dCache, dSwap, dSwapIO *prometheus.Desc
	dOOM, dDirty, dPSI     *prometheus.Desc
}

func NewMem(src *procfs.Source, host string, interval time.Duration) *Mem {
	b := base{host: host}
	return &Mem{
		base:     b,
		src:      src,
		interval: interval,
		pageSize: float64(os.Getpagesize()),
		dTotal:   b.desc("beacon_mem_total_bytes", "Total usable memory."),
		dUsed:    b.desc("beacon_mem_used_bytes", "Memory in use (total - available)."),
		dRatio:   b.desc("beacon_mem_used_ratio", "Memory in use as a fraction of total."),
		dCache:   b.desc("beacon_mem_detail_bytes", "Memory breakdown by kind.", "kind"),
		dSwap:    b.desc("beacon_mem_swap_used_ratio", "Swap in use as a fraction of swap total."),
		dSwapIO:  b.desc("beacon_mem_swap_io_bytes_total", "Pages swapped in or out since boot.", "direction"),
		dOOM:     b.desc("beacon_mem_oom_kill_total", "OOM kills since boot."),
		dDirty:   b.desc("beacon_mem_dirty_bytes", "Memory waiting to be written to disk.", "kind"),
		dPSI:     b.desc("beacon_psi_memory_avg10", "Memory pressure stall information, 10 second average (percent).", "kind"),
	}
}

func (m *Mem) Name() string            { return "mem" }
func (m *Mem) Interval() time.Duration { return m.interval }

func (m *Mem) Refresh(ctx context.Context) error {
	raw, err := m.src.ReadProc("meminfo")
	if err != nil {
		return err
	}
	mi := parseMeminfo(raw)

	s := &memSnapshot{
		total:     mi["MemTotal"],
		available: mi["MemAvailable"],
		cached:    mi["Cached"],
		buffers:   mi["Buffers"],
		slab:      mi["Slab"],
		shmem:     mi["Shmem"],
		dirty:     mi["Dirty"],
		writeback: mi["Writeback"],
	}
	if s.total > 0 {
		s.used = s.total - s.available
		if s.used < 0 {
			s.used = 0
		}
		s.usedRatio = s.used / s.total
	}

	if swapTotal := mi["SwapTotal"]; swapTotal > 0 {
		s.swapRatio = (swapTotal - mi["SwapFree"]) / swapTotal
	}

	if vm, err := m.src.ReadProc("vmstat"); err == nil {
		v := parseVMStat(vm)
		s.swapIn = v["pswpin"] * m.pageSize
		s.swapOut = v["pswpout"] * m.pageSize
		s.oomKill = v["oom_kill"]
	}

	if pb, err := m.src.ReadProc("pressure", "memory"); err == nil {
		some, full := parsePSI(pb)
		s.psiSome, s.psiFull, s.hasPSI = some["avg10"], full["avg10"], true
	}

	m.mu.Lock()
	m.snap = s
	m.mu.Unlock()
	return nil
}

func (m *Mem) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		m.dTotal, m.dUsed, m.dRatio, m.dCache, m.dSwap,
		m.dSwapIO, m.dOOM, m.dDirty, m.dPSI,
	} {
		ch <- d
	}
}

func (m *Mem) Collect(ch chan<- prometheus.Metric) {
	m.mu.RLock()
	s := m.snap
	m.mu.RUnlock()
	if s == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(m.dTotal, prometheus.GaugeValue, s.total)
	ch <- prometheus.MustNewConstMetric(m.dUsed, prometheus.GaugeValue, s.used)
	ch <- prometheus.MustNewConstMetric(m.dRatio, prometheus.GaugeValue, s.usedRatio)
	for kind, v := range map[string]float64{
		"cached": s.cached, "buffers": s.buffers, "slab": s.slab, "shmem": s.shmem,
	} {
		ch <- prometheus.MustNewConstMetric(m.dCache, prometheus.GaugeValue, v, kind)
	}
	ch <- prometheus.MustNewConstMetric(m.dSwap, prometheus.GaugeValue, s.swapRatio)
	ch <- prometheus.MustNewConstMetric(m.dSwapIO, prometheus.CounterValue, s.swapIn, "in")
	ch <- prometheus.MustNewConstMetric(m.dSwapIO, prometheus.CounterValue, s.swapOut, "out")
	ch <- prometheus.MustNewConstMetric(m.dOOM, prometheus.CounterValue, s.oomKill)
	ch <- prometheus.MustNewConstMetric(m.dDirty, prometheus.GaugeValue, s.dirty, "dirty")
	ch <- prometheus.MustNewConstMetric(m.dDirty, prometheus.GaugeValue, s.writeback, "writeback")
	if s.hasPSI {
		ch <- prometheus.MustNewConstMetric(m.dPSI, prometheus.GaugeValue, s.psiSome, "some")
		ch <- prometheus.MustNewConstMetric(m.dPSI, prometheus.GaugeValue, s.psiFull, "full")
	}
}

package collector

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/yqjwxz/beacon/internal/procfs"
)

func fixtureSource() *procfs.Source {
	return procfs.New("testdata/proc", "testdata/sys")
}

func gather(t *testing.T, cs ...prometheus.Collector) []*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range cs {
		reg.MustRegister(c)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return mfs
}

func metricValue(t *testing.T, mfs []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if !matchLabels(m, labels) {
				continue
			}
			switch {
			case m.Gauge != nil:
				return m.Gauge.GetValue()
			case m.Counter != nil:
				return m.Counter.GetValue()
			}
		}
	}
	t.Fatalf("metric %s%v not found", name, labels)
	return 0
}

func matchLabels(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, l := range m.GetLabel() {
		got[l.GetName()] = l.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestParseProcStat(t *testing.T) {
	b, err := os.ReadFile("testdata/proc/stat")
	if err != nil {
		t.Fatal(err)
	}
	cpu, s, err := parseProcStat(b)
	if err != nil {
		t.Fatal(err)
	}
	if cpu.User != 1000 || cpu.System != 300 || cpu.Idle != 8000 || cpu.Steal != 20 {
		t.Errorf("unexpected cpu times: %+v", cpu)
	}
	if s.Ctxt != 9876543 || s.ProcsRunning != 2 || s.ProcsBlocked != 1 {
		t.Errorf("unexpected scalars: %+v", s)
	}
}

func TestParseLoadAndPSI(t *testing.T) {
	lb, _ := os.ReadFile("testdata/proc/loadavg")
	l1, l5, l15, err := parseLoadavg(lb)
	if err != nil || l1 != 0.52 || l5 != 0.41 || l15 != 0.38 {
		t.Fatalf("loadavg = %v %v %v (%v)", l1, l5, l15, err)
	}

	pb, _ := os.ReadFile("testdata/proc/pressure/memory")
	some, full := parsePSI(pb)
	if some["avg10"] != 2.5 || full["avg10"] != 0.75 || some["avg300"] != 0.6 {
		t.Fatalf("psi = %v / %v", some, full)
	}
}

func TestParseMeminfo(t *testing.T) {
	b, _ := os.ReadFile("testdata/proc/meminfo")
	mi := parseMeminfo(b)
	if mi["MemTotal"] != 16384000*1024 {
		t.Errorf("MemTotal = %v", mi["MemTotal"])
	}
	if mi["SwapFree"] != 1024000*1024 {
		t.Errorf("SwapFree = %v", mi["SwapFree"])
	}
}

func TestParseMounts(t *testing.T) {
	b, _ := os.ReadFile("testdata/proc/mounts")
	ms := parseMounts(b)
	if len(ms) != 4 {
		t.Fatalf("want 4 mounts, got %d: %+v", len(ms), ms)
	}
	if ms[0].Mountpoint != "/" || ms[0].FSType != "ext4" {
		t.Errorf("first mount = %+v", ms[0])
	}
	var boot *mount
	for i := range ms {
		if ms[i].Mountpoint == "/boot" {
			boot = &ms[i]
		}
	}
	if boot == nil || !boot.ReadOnly {
		t.Errorf("expected /boot to be read-only: %+v", boot)
	}
}

func TestParseDiskstatsFilters(t *testing.T) {
	b, _ := os.ReadFile("testdata/proc/diskstats")
	all := parseDiskstats(b)
	if len(all) != 4 {
		t.Fatalf("want 4 devices, got %d", len(all))
	}
	src := fixtureSource()
	if !isWholeDevice(src, "nvme0n1") {
		t.Error("nvme0n1 should be a whole device")
	}
	if isWholeDevice(src, "nvme0n1p1") {
		t.Error("nvme0n1p1 is a partition")
	}
	if isWholeDevice(src, "loop0") {
		t.Error("loop0 should be skipped")
	}
	if !isWholeDevice(src, "sda") {
		t.Error("sda should be accepted by the name fallback")
	}
}

func TestParseNetDevAndTCP(t *testing.T) {
	b, _ := os.ReadFile("testdata/proc/net/dev")
	ifaces := parseNetDev(b)
	if len(ifaces) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(ifaces))
	}
	if ifaces["eth0"].RxBytes != 5000000 || ifaces["eth0"].TxDrop != 0 || ifaces["eth0"].RxDrop != 1 {
		t.Errorf("eth0 = %+v", ifaces["eth0"])
	}

	tb, _ := os.ReadFile("testdata/proc/net/tcp")
	states := parseTCPStates(tb)
	if states["listen"] != 1 || states["established"] != 1 || states["time_wait"] != 1 {
		t.Errorf("tcp states = %v", states)
	}
}

func TestParseSNMP(t *testing.T) {
	b, _ := os.ReadFile("testdata/proc/net/snmp")
	m := parseSNMP(b)
	if m["OutSegs"] != 800000 || m["RetransSegs"] != 1200 {
		t.Fatalf("snmp = %v", m)
	}
}

func TestCPURatesAcrossTwoSamples(t *testing.T) {
	dir := t.TempDir()
	write := func(stat string) {
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cpu 100 0 0 900 0 0 0 0 0 0\n")
	c := NewCPU(procfs.New(dir, dir), "testhost", 5*time.Second)
	ctx := context.Background()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	write("cpu 200 0 0 1800 0 0 0 0 0 0\n")
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	mfs := gather(t, c)
	user := metricValue(t, mfs, "beacon_cpu_usage_ratio", map[string]string{"mode": "user", "host": "testhost"})
	if math.Abs(user-0.1) > 1e-9 {
		t.Errorf("user ratio = %v, want 0.1", user)
	}
	idle := metricValue(t, mfs, "beacon_cpu_usage_ratio", map[string]string{"mode": "idle"})
	if math.Abs(idle-0.9) > 1e-9 {
		t.Errorf("idle ratio = %v, want 0.9", idle)
	}
}

func TestMemRefresh(t *testing.T) {
	c := NewMem(fixtureSource(), "h1", 5*time.Second)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mfs := gather(t, c)
	used := metricValue(t, mfs, "beacon_mem_used_bytes", nil)
	if used != (16384000-9000000)*1024 {
		t.Errorf("used = %v", used)
	}
	ratio := metricValue(t, mfs, "beacon_mem_used_ratio", nil)
	if math.Abs(ratio-float64(16384000-9000000)/16384000) > 1e-9 {
		t.Errorf("ratio = %v", ratio)
	}
	if v := metricValue(t, mfs, "beacon_mem_oom_kill_total", nil); v != 1 {
		t.Errorf("oom kill = %v", v)
	}
}

func TestNetRefresh(t *testing.T) {
	c := NewNet(fixtureSource(), "h1", 5*time.Second)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mfs := gather(t, c)
	if v := metricValue(t, mfs, "beacon_net_rx_bytes_total", map[string]string{"iface": "eth0"}); v != 5000000 {
		t.Errorf("rx bytes = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_net_up", map[string]string{"iface": "eth0"}); v != 1 {
		t.Errorf("up = %v", v)
	}
	// listen appears in tcp and tcp6 fixtures.
	if v := metricValue(t, mfs, "beacon_tcp_conns", map[string]string{"state": "listen"}); v != 2 {
		t.Errorf("listen = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_conntrack_used_ratio", nil); math.Abs(v-512.0/65536.0) > 1e-9 {
		t.Errorf("conntrack ratio = %v", v)
	}
}

func TestDiskRefreshMissingMount(t *testing.T) {
	c := NewDisk(fixtureSource(), "h1", 15*time.Second, excludeRE(t))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mfs := gather(t, c)
	if v := metricValue(t, mfs, "beacon_disk_mount_present", map[string]string{"mount": "/mnt/missing"}); v != 0 {
		t.Errorf("missing mount present = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_disk_readonly", map[string]string{"mount": "/boot"}); v != 1 {
		t.Errorf("boot readonly = %v", v)
	}
	// loop0 must not appear at all.
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "device" && l.GetValue() == "loop0" {
					t.Fatalf("loop device leaked into metrics: %s", mf.GetName())
				}
			}
		}
	}
}

func excludeRE(t *testing.T) *regexp.Regexp {
	t.Helper()
	return regexp.MustCompile(`^/(run|var/lib/docker/.+)($|/)`)
}

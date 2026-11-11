package flow

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseConntrack(t *testing.T) {
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.5 dst=1.1.1.1 sport=51234 dport=443 src=1.1.1.1 dst=192.168.1.5 sport=443 dport=51234 [ASSURED] mark=0 use=1"
	e, err := ParseConntrack(line)
	if err != nil {
		t.Fatal(err)
	}
	if e.Family != "ipv4" || e.Proto != "tcp" || e.State != "ESTABLISHED" {
		t.Fatalf("basic fields = %+v", e)
	}
	if e.Src != "192.168.1.5" || e.Dst != "1.1.1.1" {
		t.Fatalf("tuple = %s -> %s", e.Src, e.Dst)
	}
	if e.SPort != 51234 || e.DPort != 443 {
		t.Fatalf("ports = %d -> %d", e.SPort, e.DPort)
	}
	if e.Unreplied {
		t.Fatal("ASSURED entry marked unreplied")
	}
}

func TestParseConntrackUnrepliedAndBytes(t *testing.T) {
	line := "ipv4 2 tcp 6 117 SYN_SENT src=10.0.0.9 dst=45.9.9.9 sport=40000 dport=22 packets=3 bytes=180 src=45.9.9.9 dst=10.0.0.9 sport=22 dport=40000 packets=0 bytes=0 [UNREPLIED] mark=0 use=1"
	e, err := ParseConntrack(line)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Unreplied {
		t.Fatal("UNREPLIED flag lost")
	}
	if !e.HasBytes || e.BytesOut != 180 || e.BytesIn != 0 {
		t.Fatalf("bytes = %+v", e)
	}
	if e.Src != "10.0.0.9" || e.DPort != 22 {
		t.Fatalf("tuple messed up by reply: %+v", e)
	}
}

func TestReadConntrackCapsEntries(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "ipv4 2 tcp 6 100 ESTABLISHED src=10.0.0.1 dst=8.8.8.8 sport=%d dport=443 src=8.8.8.8 dst=10.0.0.1 sport=443 dport=%d [ASSURED] mark=0 use=1\n", 30000+i, 30000+i)
	}
	entries, total, err := ReadConntrack(strings.NewReader(b.String()), 40)
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 {
		t.Errorf("total = %d", total)
	}
	if len(entries) != 40 {
		t.Errorf("entries = %d, want cap 40", len(entries))
	}
}

func localSet() map[string]bool {
	return map[string]bool{"10.0.0.1": true, "127.0.0.1": true}
}

func TestAggregateDirections(t *testing.T) {
	entries := []Entry{
		{Family: "ipv4", Proto: "tcp", Src: "10.0.0.1", Dst: "1.1.1.1", SPort: 50000, DPort: 443},
		{Family: "ipv4", Proto: "tcp", Src: "9.9.9.9", Dst: "10.0.0.1", SPort: 40000, DPort: 22, Unreplied: true},
		{Family: "ipv4", Proto: "tcp", Src: "10.0.0.1", Dst: "10.0.0.1", SPort: 1, DPort: 2},
	}
	s := Aggregate(entries, localSet(), time.Now())
	if s.Out.Conns != 1 || s.In.Conns != 1 {
		t.Fatalf("in/out = %+v / %+v", s.In, s.Out)
	}
	if s.In.Unreplied != 1 {
		t.Errorf("unreplied = %d", s.In.Unreplied)
	}
	if s.Ports["out|443"].Conns != 1 || s.Ports["in|22"].Conns != 1 {
		t.Errorf("ports = %+v", s.Ports)
	}
	if len(s.UniqueDstPortsIn) != 1 {
		t.Errorf("unique in ports = %v", s.UniqueDstPortsIn)
	}
	if s.LocalSkipped != 1 {
		t.Errorf("local skipped = %d, want 1", s.LocalSkipped)
	}
}

func TestBucketBoundsCardinality(t *testing.T) {
	if Bucket(443) != "443" {
		t.Errorf("443 = %s", Bucket(443))
	}
	if Bucket(54321) != "other" {
		t.Errorf("54321 = %s", Bucket(54321))
	}
}

func scanSample() *Sample {
	s := NewSample()
	s.In = Side{Conns: 100, Unreplied: 90}
	for p := 1; p <= 30; p++ {
		s.UniqueDstPortsIn[p] = struct{}{}
	}
	return s
}

func TestDetectPortScanIn(t *testing.T) {
	f := Detect(scanSample(), EgressContext{})
	if len(f) != 1 || f[0].Kind != "port_scan_in" || f[0].Severity != "P1" {
		t.Fatalf("findings = %+v", f)
	}
	if f[0].Evidence["unique_dst_ports"] != 30 {
		t.Errorf("evidence = %+v", f[0].Evidence)
	}
}

func TestDetectScanOut(t *testing.T) {
	s := NewSample()
	for p := 1; p <= 40; p++ {
		s.UniqueDstPortsOut[p] = struct{}{}
	}
	f := Detect(s, EgressContext{})
	if len(f) != 1 || f[0].Kind != "port_scan_out" || f[0].Severity != "P0" {
		t.Fatalf("findings = %+v", f)
	}
}

func TestDetectSSHBruteforce(t *testing.T) {
	s := NewSample()
	s.Ports["in|22"] = PortAgg{Conns: 50, Unreplied: 50}
	f := Detect(s, EgressContext{})
	if len(f) != 1 || f[0].Kind != "ssh_bruteforce" {
		t.Fatalf("findings = %+v", f)
	}
	if f[0].Evidence["port"] != "22" {
		t.Errorf("evidence = %+v", f[0].Evidence)
	}
}

func TestDetectSuspiciousDport(t *testing.T) {
	s := NewSample()
	s.SuspiciousOut[3333] = 4
	f := Detect(s, EgressContext{})
	if len(f) != 1 || f[0].Kind != "suspicious_dport" {
		t.Fatalf("findings = %+v", f)
	}
	if f[0].Evidence["category"] != "mining" {
		t.Errorf("evidence = %+v", f[0].Evidence)
	}
}

func TestDetectEgressBurstNeedsStreak(t *testing.T) {
	hot := EgressContext{BPS: 10 << 20, P95: 100 << 10, Score: 10, Samples: 30, Streak: 1}
	if f := Detect(NewSample(), hot); len(f) != 0 {
		t.Fatal("one sample must not fire")
	}
	hot.Streak = 3
	f := Detect(NewSample(), hot)
	if len(f) != 1 || f[0].Kind != "egress_burst" {
		t.Fatalf("findings = %+v", f)
	}
}

func TestBaselineQuantiles(t *testing.T) {
	b := LoadBaseline("")
	at := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		b.Observe(at, float64(1_000_000+i*10_000)) // 1.0MB/s .. 1.99MB/s
	}
	p50, p95, mad, n := b.Stats(at)
	if n != 100 {
		t.Fatalf("count = %d", n)
	}
	if p50 < 1_400_000 || p50 > 1_600_000 {
		t.Errorf("p50 = %f", p50)
	}
	if p95 < 1_800_000 || p95 > 1_950_000 {
		t.Errorf("p95 = %f", p95)
	}
	if mad <= 0 {
		t.Errorf("mad = %f", mad)
	}

	if score, _, _ := b.Score(at, 1_200_000); score != 0 {
		t.Errorf("normal value scored %f, want 0", score)
	}
	if score, _, _ := b.Score(at, 5_000_000); score <= 3 {
		t.Errorf("spike scored %f, want > 3", score)
	}
}

func TestBaselineColdStart(t *testing.T) {
	b := LoadBaseline("")
	at := time.Now()
	b.Observe(at, 1000)
	if score, _, n := b.Score(at, 1<<30); score != 0 || n != 1 {
		t.Fatalf("cold slot must not score: score=%f n=%d", score, n)
	}
}

func TestBaselinePersist(t *testing.T) {
	path := t.TempDir() + "/baseline.json"
	b := LoadBaseline(path)
	at := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		b.Observe(at, 5000)
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	b2 := LoadBaseline(path)
	if _, _, _, n := b2.Stats(at); n != 30 {
		t.Fatalf("reloaded count = %d", n)
	}
}

func TestBaselineIgnoresOldVersion(t *testing.T) {
	path := t.TempDir() + "/baseline.json"
	if err := os.WriteFile(path, []byte(`{"version":1,"slots":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b := LoadBaseline(path)
	if _, _, _, n := b.Stats(time.Now()); n != 0 {
		t.Fatalf("old model should be discarded, got %d samples", n)
	}
}

func TestEgressContextFloor(t *testing.T) {
	c := EgressContext{BPS: 1000, P95: 100, Score: 50, Samples: 100, Streak: 9}
	if c.Anomalous() {
		t.Fatal("tiny absolute rates must not alert")
	}
}

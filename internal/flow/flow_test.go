package flow

import (
	"fmt"
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

func TestDetectEgressBurstNeedsWarmup(t *testing.T) {
	hot := EgressContext{BPS: 10 << 20, Expected: 100 << 10, Samples: 1, Multiplier: 3}
	if f := Detect(NewSample(), hot); len(f) != 0 {
		t.Fatal("must not fire before warmup")
	}
	warm := EgressContext{BPS: 10 << 20, Expected: 100 << 10, Samples: 10, Multiplier: 3}
	f := Detect(NewSample(), warm)
	if len(f) != 1 || f[0].Kind != "egress_burst" {
		t.Fatalf("findings = %+v", f)
	}
}

func TestBaselineLearnAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/baseline.json"
	b := LoadBaseline(path)
	at := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		b.Observe(at, 1000)
	}
	if got := b.Expected(at); got < 900 || got > 1100 {
		t.Fatalf("expected ~1000, got %f", got)
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}

	b2 := LoadBaseline(path)
	if got := b2.Expected(at); got < 900 || got > 1100 {
		t.Fatalf("reloaded baseline = %f", got)
	}
	if b2.Samples(at) != 10 {
		t.Fatalf("samples = %d", b2.Samples(at))
	}
}

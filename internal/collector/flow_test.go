package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yqjwxz/beacon/internal/procfs"
)

func flowFixture(t *testing.T, conntrack string) (*procfs.Source, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "net", "nf_conntrack"), []byte(conntrack), 0o644); err != nil {
		t.Fatal(err)
	}
	dev := "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
		"  eth0: 1000 10 0 0 0 0 0 0 5000 50 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "net", "dev"), []byte(dev), 0o644); err != nil {
		t.Fatal(err)
	}
	return procfs.New(dir, dir), filepath.Join(dir, "flow", "baseline.json")
}

func TestFlowDetectsSSHBruteforce(t *testing.T) {
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, "ipv4 2 tcp 6 100 SYN_RECV src=203.0.113."+itoa(i)+" dst=127.0.0.1 sport="+itoa(40000+i)+" dport=22 src=127.0.0.1 dst=203.0.113."+itoa(i)+" sport=22 dport="+itoa(40000+i)+" [UNREPLIED] mark=0 use=1")
	}
	src, baseline := flowFixture(t, strings.Join(lines, "\n")+"\n")

	sink := &captureSink{}
	f := NewFlow(src, "h1", 15*time.Second, sink, FlowOptions{MaxEntries: 4096, TopK: 10, EgressMultiplier: 3, BaselinePath: baseline, Cooldown: time.Minute})
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	evs := sink.all()
	if len(evs) != 1 || evs[0].Type != "ssh_bruteforce" || evs[0].Severity != "P0" {
		t.Fatalf("events = %+v", evs)
	}

	mfs := gather(t, f)
	if v := metricValue(t, mfs, "beacon_flow_conns", map[string]string{"dir": "in"}); v != 25 {
		t.Errorf("inbound conns = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_flow_unreplied", map[string]string{"dir": "in"}); v != 25 {
		t.Errorf("unreplied = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_flow_anomaly_score", map[string]string{"kind": "ssh_bruteforce"}); v != 25 {
		t.Errorf("anomaly score = %v", v)
	}
}

func TestFlowDetectsInboundScan(t *testing.T) {
	var lines []string
	for p := 1; p <= 30; p++ {
		lines = append(lines, "ipv4 2 tcp 6 100 SYN_SENT src=198.51.100.7 dst=127.0.0.1 sport=5000 dport="+itoa(1000+p)+" src=127.0.0.1 dst=198.51.100.7 sport="+itoa(1000+p)+" dport=5000 [UNREPLIED] mark=0 use=1")
	}
	src, baseline := flowFixture(t, strings.Join(lines, "\n")+"\n")

	sink := &captureSink{}
	f := NewFlow(src, "h1", 15*time.Second, sink, FlowOptions{MaxEntries: 4096, TopK: 10, EgressMultiplier: 3, BaselinePath: baseline, Cooldown: time.Minute})
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs := sink.all()
	found := false
	for _, e := range evs {
		if e.Type == "port_scan_in" {
			found = true
		}
	}
	if !found {
		t.Fatalf("events = %+v", evs)
	}
	if v := metricValue(t, gather(t, f), "beacon_flow_unique_dst_ports", map[string]string{"dir": "in"}); v != 30 {
		t.Errorf("unique dst ports = %v", v)
	}
}

func TestFlowCooldownSuppressesRepeats(t *testing.T) {
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, "ipv4 2 tcp 6 100 SYN_RECV src=203.0.113."+itoa(i)+" dst=127.0.0.1 sport=40000 dport=22 src=127.0.0.1 dst=203.0.113."+itoa(i)+" sport=22 dport=40000 [UNREPLIED] mark=0 use=1")
	}
	src, baseline := flowFixture(t, strings.Join(lines, "\n")+"\n")
	sink := &captureSink{}
	f := NewFlow(src, "h1", 15*time.Second, sink, FlowOptions{MaxEntries: 4096, TopK: 10, EgressMultiplier: 3, BaselinePath: baseline, Cooldown: time.Hour})

	for i := 0; i < 3; i++ {
		if err := f.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sink.all()); got != 1 {
		t.Fatalf("events = %d, want 1 within cooldown", got)
	}
}

func TestFlowMissingConntrackDegrades(t *testing.T) {
	src := procfs.New(t.TempDir(), t.TempDir())
	f := NewFlow(src, "h1", 15*time.Second, &captureSink{}, FlowOptions{BaselinePath: filepath.Join(t.TempDir(), "b.json")})
	if err := f.Refresh(context.Background()); err == nil {
		t.Fatal("expected an error when conntrack is unavailable")
	}
	// A failed refresh must leave the collector safe to scrape.
	mfs := gather(t, f)
	if len(mfs) != 0 {
		t.Fatalf("expected no metrics, got %d families", len(mfs))
	}
}

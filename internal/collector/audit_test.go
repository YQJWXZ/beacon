package collector

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yqjwxz/beacon/internal/audit"
	"github.com/yqjwxz/beacon/internal/procfs"
)

type fakeRunner struct {
	mu  sync.Mutex
	out map[string][]byte
}

func (f *fakeRunner) set(key string, v []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out[key] = v
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.out[key]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureSink) Emit(e audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) all() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Event(nil), c.events...)
}

func nftDoc(rules string) []byte {
	return []byte(`{"nftables":[
	{"table":{"family":"inet","name":"filter","handle":1}},
	{"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}}` + rules + `]}`)
}

func nftRule(handle int, port int) string {
	return `,{"rule":{"family":"inet","table":"filter","chain":"input","handle":` +
		itoa(handle) + `,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":` +
		itoa(port) + `}},{"accept":null}]}}`
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func TestFirewallDetectsChange(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "fw.json")
	sink := &captureSink{}

	r := &fakeRunner{out: map[string][]byte{}}
	r.set("nft -j list ruleset", nftDoc(nftRule(2, 22)+nftRule(3, 443)))

	fw := NewFirewall(r, "h1", time.Minute, sink, state)
	ctx := context.Background()
	if err := fw.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("baseline must not emit events, got %+v", got)
	}

	// A rule appears, and the baseline must survive in the state file.
	r.set("nft -j list ruleset", nftDoc(nftRule(2, 22)+nftRule(3, 443)+nftRule(4, 6379)))
	if err := fw.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Type != "fw_change" {
		t.Fatalf("events = %+v", evs)
	}
	if evs[0].Severity != "P1" {
		t.Errorf("severity = %s", evs[0].Severity)
	}

	mfs := gather(t, fw)
	if v := metricValue(t, mfs, "beacon_fw_rules_total", map[string]string{"table": "filter"}); v != 3 {
		t.Errorf("rules total = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_fw_risky_rules", nil); v != 2 {
		t.Errorf("risky = %v (22 and 6379 are open to the world)", v)
	}
	if v := metricValue(t, mfs, "beacon_fw_ipv6_covered", nil); v != 1 {
		t.Errorf("ipv6 covered = %v", v)
	}
}

func TestFirewallFlushIsP0(t *testing.T) {
	dir := t.TempDir()
	sink := &captureSink{}
	r := &fakeRunner{out: map[string][]byte{}}
	r.set("nft -j list ruleset", nftDoc(nftRule(2, 22)+nftRule(3, 443)+nftRule(4, 80)))

	fw := NewFirewall(r, "h1", time.Minute, sink, filepath.Join(dir, "fw.json"))
	ctx := context.Background()
	if err := fw.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	r.set("nft -j list ruleset", nftDoc(""))
	if err := fw.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Severity != "P0" {
		t.Fatalf("flush should be P0: %+v", evs)
	}
	if flushed, _ := evs[0].Data["flushed"].(bool); !flushed {
		t.Error("event should be marked flushed")
	}
}

func TestPortsDetectNewListener(t *testing.T) {
	dir := t.TempDir()
	sink := &captureSink{}
	r := &fakeRunner{out: map[string][]byte{}}
	base := "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3)) uid:0 ino:1 sk:1\n"
	r.set("ss -Htulpen", []byte(base))

	p := NewPorts(procfs.New(dir, dir), r, "h1", time.Minute, sink, filepath.Join(dir, "ports.json"),
		ExposureConfig{Allow: []string{"22"}})
	ctx := context.Background()
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sink.all(); len(got) != 0 {
		t.Fatalf("baseline must be silent, got %+v", got)
	}

	r.set("ss -Htulpen", []byte(base+"tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:((\"redis\",pid=900,fd=3)) uid:0 ino:2 sk:2\n"))
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Type != "port_added" || evs[0].Severity != "P0" {
		t.Fatalf("events = %+v", evs)
	}

	mfs := gather(t, p)
	if v := metricValue(t, mfs, "beacon_port_new_total", nil); v != 1 {
		t.Errorf("new total = %v", v)
	}
	if v := metricValue(t, mfs, "beacon_exposure_sg_unknown", nil); v != 1 {
		t.Errorf("sg unknown = %v", v)
	}
}

func TestPortsWidenedFromLoopback(t *testing.T) {
	dir := t.TempDir()
	sink := &captureSink{}
	r := &fakeRunner{out: map[string][]byte{}}
	loopback := "tcp LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:((\"redis\",pid=900,fd=3)) uid:999 ino:1 sk:1\n"
	r.set("ss -Htulpen", []byte(loopback))

	p := NewPorts(procfs.New(dir, dir), r, "h1", time.Minute, sink, filepath.Join(dir, "ports.json"), ExposureConfig{})
	ctx := context.Background()
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	r.set("ss -Htulpen", []byte("tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:((\"redis\",pid=900,fd=3)) uid:999 ino:1 sk:1\n"))
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Type != "port_scope_widened" || evs[0].Severity != "P0" {
		t.Fatalf("events = %+v", evs)
	}
}

package audit

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseNFT(t *testing.T) {
	s, err := ParseNFT(readFixture(t, "nft.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Backend != BackendNFT {
		t.Errorf("backend = %s", s.Backend)
	}
	if len(s.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(s.Rules))
	}
	if got := s.Policy["inet/filter/input"]; got != "drop" {
		t.Errorf("policy = %q", got)
	}
	if !s.IPv6Covered {
		t.Error("inet table should cover IPv6")
	}

	risky := RiskyRules(s)
	if ports := riskyPortSet(risky); !ports["22"] || !ports["6379"] || ports["3306"] || ports["443"] {
		t.Fatalf("risky = %+v", risky)
	}
	// 3306 is scoped to 10.0.0.0/8 and must not be risky.
	for _, r := range s.Rules {
		if r.DPort == "3306" && r.SAddr != "10.0.0.0/8" {
			t.Errorf("saddr parse failed: %+v", r)
		}
	}
}

func TestParseIptables(t *testing.T) {
	s, err := ParseIptables(readFixture(t, "iptables.save"), "ip")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(s.Rules))
	}
	if s.Policy["ip/filter/INPUT"] != "drop" {
		t.Errorf("policy = %v", s.Policy)
	}
	set := riskyPortSet(RiskyRules(s))
	if !set["22"] || !set["6379"] || set["3306"] {
		t.Fatalf("risky = %+v", set)
	}
	if len(OpenPolicies(s)) != 0 {
		t.Errorf("INPUT drop should not be open: %v", OpenPolicies(s))
	}
}

func TestParseUFW(t *testing.T) {
	s, err := ParseUFW(readFixture(t, "ufw.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) != 4 {
		t.Fatalf("rules = %d, want 4: %+v", len(s.Rules), s.Rules)
	}
	if s.Policy["ufw/input"] != "deny" {
		t.Errorf("policy = %v", s.Policy)
	}
	if !s.IPv6Covered {
		t.Error("v6 rule present, coverage should be true")
	}
	risky := riskyPortSet(RiskyRules(s))
	if !risky["22"] || !risky["3306"] || risky["443"] {
		t.Fatalf("risky = %+v", risky)
	}
}

func TestParseFirewalld(t *testing.T) {
	s, err := ParseFirewalld(readFixture(t, "firewalld.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) != 3 {
		t.Fatalf("rules = %d, want 3: %+v", len(s.Rules), s.Rules)
	}
	if got := riskyPortSet(RiskyRules(s)); !got["22"] || !got["6379"] {
		t.Fatalf("risky = %+v", got)
	}
}

func TestParseSS(t *testing.T) {
	ls := ParseSS(readFixture(t, "ss.txt"))
	if len(ls) != 5 {
		t.Fatalf("listeners = %d: %+v", len(ls), ls)
	}
	byKey := map[string]Listen{}
	for _, l := range ls {
		byKey[l.AddrPort()] = l
	}
	if l, ok := byKey["0.0.0.0:22"]; !ok || l.Comm != "sshd" || l.PID != 812 || l.UID != 0 {
		t.Errorf("sshd listener = %+v", byKey["0.0.0.0:22"])
	}
	if l, ok := byKey["127.0.0.1:8083"]; !ok || !l.Loopback() || l.Public() {
		t.Errorf("loopback listener = %+v", l)
	}
	if l, ok := byKey["0.0.0.0:80"]; !ok || l.Comm != "nginx" || !l.Public() {
		t.Errorf("wildcard listener = %+v", l)
	}
}

func TestPortDiff(t *testing.T) {
	before := []Listen{
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6379, Comm: "redis-server"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Comm: "sshd"},
	}
	after := []Listen{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, Comm: "redis-server"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Comm: "sshd"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 9090, Comm: "cockpit"},
	}
	d := DiffListens(before, after)
	if len(d.Added) != 1 || d.Added[0].Port != 9090 {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Widened) != 1 || d.Widened[0].After.Addr != "0.0.0.0" {
		t.Errorf("widened = %+v", d.Widened)
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %+v", d.Removed)
	}
}

func TestExposureUnexpected(t *testing.T) {
	listens := []Listen{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Comm: "sshd"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, Comm: "redis"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 9090, Comm: "x"},
	}
	reach := map[string]bool{"tcp/22": true, "tcp/6379": true, "tcp/9090": true}
	exp := Evaluate(ExposureInput{
		Listen: listens, Reachable: reach,
		Allow: NewMatcher([]string{"22"}), SGKnown: false,
	})
	if len(exp.Unexpected) != 1 || exp.Unexpected[0].Port != 6379 {
		t.Fatalf("unexpected = %+v", exp.Unexpected)
	}
	if !exp.SGUnknown {
		t.Error("sg should be unknown")
	}
	if exp.ProbeUnknown {
		t.Error("probe was provided")
	}
}

func TestExposureWithoutProbe(t *testing.T) {
	exp := Evaluate(ExposureInput{Listen: []Listen{{Proto: "tcp", Addr: "0.0.0.0", Port: 6379}}})
	if len(exp.Unexpected) != 0 {
		t.Fatalf("no probe must not produce findings: %+v", exp.Unexpected)
	}
	if !exp.ProbeUnknown {
		t.Error("probe should be unknown")
	}
}

func TestDiffSnapshotsFlush(t *testing.T) {
	before := &Snapshot{Hash: "a", Rules: make([]Rule, 12), Policy: map[string]string{}}
	after := &Snapshot{Hash: "b", Rules: nil, Policy: map[string]string{}}
	d := DiffSnapshots(before, after)
	if !d.Flushed {
		t.Fatal("expected flush detection")
	}
}

func TestPolicyChange(t *testing.T) {
	before := &Snapshot{Hash: "a", Policy: map[string]string{"ip/filter/INPUT": "drop"}}
	after := &Snapshot{Hash: "b", Policy: map[string]string{"ip/filter/INPUT": "accept"}}
	d := DiffSnapshots(before, after)
	if len(d.PolicyChanges) != 1 || d.PolicyChanges[0].After != "accept" {
		t.Fatalf("policy changes = %+v", d.PolicyChanges)
	}
}

type fakeRunner map[string][]byte

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if b, ok := f[key]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func TestCollectFirewallPrefersUFW(t *testing.T) {
	r := fakeRunner{
		"ufw status verbose":  readFixture(t, "ufw.txt"),
		"nft -j list ruleset": readFixture(t, "nft.json"),
	}
	s, active, err := CollectFirewall(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !active || s.Backend != BackendUFW {
		t.Fatalf("backend = %s active=%v", s.Backend, active)
	}
	if s.At.IsZero() {
		t.Error("snapshot time not set")
	}
}

func TestCollectFirewallNoBackend(t *testing.T) {
	s, active, err := CollectFirewall(context.Background(), fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if active || s.Backend != BackendNone {
		t.Fatalf("backend = %s active=%v", s.Backend, active)
	}
}

func TestSnapshotHashStable(t *testing.T) {
	b := readFixture(t, "nft.json")
	s1, _ := ParseNFT(b)
	s2, _ := ParseNFT(b)
	if s1.Hash != s2.Hash {
		t.Fatal("hash must be deterministic")
	}
	if !reflect.DeepEqual(s1.Rules, s2.Rules) {
		t.Fatal("rule order must be deterministic")
	}
	_ = time.Now
}

func riskyPortSet(rules []Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[r.DPort] = true
	}
	return out
}

func TestSplitAddrPortIPv6Zone(t *testing.T) {
	cases := []struct {
		in, addr string
		port     int
	}{
		{"[::]:22", "::", 22},
		{"[::1]:631", "::1", 631},
		{"[fe80::1]%eth0:546", "fe80::1", 546},
		{"127.0.0.1:8083", "127.0.0.1", 8083},
		{"*:80", "0.0.0.0", 80},
	}
	for _, c := range cases {
		addr, port, ok := splitAddrPort(c.in)
		if !ok || addr != c.addr || port != c.port {
			t.Errorf("%s => %s:%d ok=%v", c.in, addr, port, ok)
		}
	}
}

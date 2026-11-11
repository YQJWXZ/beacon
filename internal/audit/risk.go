package audit

import (
	"strconv"
	"strings"
)

// RiskyPorts are services that must never be reachable from the whole internet.
var RiskyPorts = []int{
	21, 22, 23, 2375, 2376, 2379, 2380, 3306, 3389,
	5432, 6379, 9200, 9300, 11211, 27017,
}

func isRiskyPort(spec string) bool {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, ":"); ok {
			loN, err1 := strconv.Atoi(lo)
			hiN, err2 := strconv.Atoi(hi)
			if err1 == nil && err2 == nil {
				for _, p := range RiskyPorts {
					if p >= loN && p <= hiN {
						return true
					}
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		for _, risky := range RiskyPorts {
			if p == risky {
				return true
			}
		}
	}
	return false
}

func openToWorld(saddr string) bool {
	switch strings.TrimSpace(strings.ToLower(saddr)) {
	case "", "anywhere", "any", "0.0.0.0/0", "::/0", "0.0.0.0":
		return true
	}
	return false
}

// RiskyRules returns accepted rules that expose a dangerous port to everyone.
func RiskyRules(s *Snapshot) []Rule {
	var out []Rule
	for _, r := range s.Rules {
		if r.Action != "accept" && r.Action != "limit" {
			continue
		}
		if r.DPort == "" || !isRiskyPort(r.DPort) {
			continue
		}
		if !openToWorld(r.SAddr) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// OpenPolicies returns chains whose default policy accepts everything.
func OpenPolicies(s *Snapshot) []string {
	var out []string
	for key, policy := range s.Policy {
		if !strings.Contains(strings.ToLower(key), "input") {
			continue
		}
		if strings.EqualFold(policy, "accept") || strings.EqualFold(policy, "allow") {
			out = append(out, key)
		}
	}
	return out
}

// ExposureInput feeds Evaluate.
type ExposureInput struct {
	Listen    []Listen
	SG        []SGEntry
	SGKnown   bool
	Reachable map[string]bool
	Allow     Matcher
}

// SGEntry is one security-group allowance, normally supplied by hand until the
// cloud provider adapters land.
type SGEntry struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	CIDR  string `json:"cidr"`
}

// Exposure is the three-set difference from the spec.
type Exposure struct {
	PublicListen     []Listen  `json:"public_listen"`
	Reachable        []Listen  `json:"reachable"`
	Unexpected       []Listen  `json:"unexpected"`
	SGOpenNoListener []SGEntry `json:"sg_open_no_listener"`
	SGUnknown        bool      `json:"sg_unknown"`
	ProbeUnknown     bool      `json:"probe_unknown"`
}

func (e Exposure) Clean() bool {
	return len(e.Unexpected) == 0 && len(e.SGOpenNoListener) == 0
}

// Evaluate intersects what listens, what is reachable and what the security
// group permits. Unknown sources never produce alerts, they only set flags.
func Evaluate(in ExposureInput) Exposure {
	out := Exposure{SGUnknown: !in.SGKnown, ProbeUnknown: in.Reachable == nil}

	for _, l := range in.Listen {
		if !l.Public() {
			continue
		}
		out.PublicListen = append(out.PublicListen, l)
		if in.Reachable == nil {
			continue
		}
		if !in.Reachable[l.Proto+"/"+strconv.Itoa(l.Port)] {
			continue
		}
		out.Reachable = append(out.Reachable, l)
		if !in.Allow.Allowed(l) {
			out.Unexpected = append(out.Unexpected, l)
		}
	}

	if in.SGKnown {
		for _, sg := range in.SG {
			found := false
			for _, l := range in.Listen {
				if l.Port == sg.Port && (sg.Proto == "" || l.Proto == sg.Proto) {
					found = true
					break
				}
			}
			if !found {
				out.SGOpenNoListener = append(out.SGOpenNoListener, sg)
			}
		}
	}
	return out
}

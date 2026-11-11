package flow

import (
	"math"
	"sort"
)

// Finding is one detector hit, ready to become an event.
type Finding struct {
	Kind     string         `json:"kind"`
	Severity string         `json:"severity"`
	Score    float64        `json:"score"`
	Evidence map[string]any `json:"evidence"`
}

// suspiciousDsts are outbound ports that essentially never belong to a healthy
// server. Redis/Mongo/Docker are included because outbound access to them is a
// classic lateral-movement and cryptomining pattern.
var suspiciousDsts = map[int]string{
	3333: "mining", 4444: "mining", 5555: "mining", 7777: "mining",
	9999: "mining", 14444: "mining", 6666: "malware", 6667: "irc-botnet",
	1080: "socks-proxy", 9050: "tor", 2375: "docker-api",
	6379: "redis", 9200: "elasticsearch", 27017: "mongodb",
}

// Detect runs the rule layer. Everything here is explainable from the sample;
// no detector depends on history except egress burst.
func Detect(s *Sample, egress EgressContext) []Finding {
	var out []Finding

	// Inbound port scan: many distinct destination ports, mostly unanswered.
	if len(s.UniqueDstPortsIn) >= 20 && s.In.Unreplied*2 >= s.In.Conns && s.In.Conns > 0 {
		out = append(out, Finding{
			Kind: "port_scan_in", Severity: "P1",
			Score: float64(len(s.UniqueDstPortsIn)),
			Evidence: map[string]any{
				"unique_dst_ports": len(s.UniqueDstPortsIn),
				"unreplied_ratio":  float64(s.In.Unreplied) / float64(s.In.Conns),
				"sample_ports":     sortedPorts(s.UniqueDstPortsIn, 10),
				"unique_sources":   len(s.UniqueSrcsIn),
			},
		})
	}

	// Outbound scan: a compromised host probing its neighbours.
	if len(s.UniqueDstPortsOut) >= 30 {
		out = append(out, Finding{
			Kind: "port_scan_out", Severity: "P0",
			Score: float64(len(s.UniqueDstPortsOut)),
			Evidence: map[string]any{
				"unique_dst_ports": len(s.UniqueDstPortsOut),
				"sample_ports":     sortedPorts(s.UniqueDstPortsOut, 10),
				"top_destinations": s.TopDestinations(5),
			},
		})
	}

	// SSH/RDP brute force: unanswered inbound connections to the admin port.
	for _, port := range []string{"22", "3389"} {
		agg := s.Ports["in|"+port]
		if agg.Unreplied >= 20 {
			out = append(out, Finding{
				Kind: "ssh_bruteforce", Severity: "P0",
				Score: float64(agg.Unreplied),
				Evidence: map[string]any{
					"port":           port,
					"unreplied":      agg.Unreplied,
					"unique_sources": len(s.UniqueSrcsIn),
				},
			})
			break
		}
	}

	// Outbound traffic to ports that should not be in a server's diet.
	for port, n := range s.SuspiciousOut {
		out = append(out, Finding{
			Kind: "suspicious_dport", Severity: "P0",
			Score: float64(n),
			Evidence: map[string]any{
				"dport": port, "category": suspiciousDsts[port],
				"connections": n, "top_destinations": s.TopDestinations(5),
			},
		})
		break // one finding per sample is enough; evidence names the rest
	}

	if egress.Anomalous() {
		out = append(out, Finding{
			Kind: "egress_burst", Severity: "P1",
			Score: egress.Score,
			Evidence: map[string]any{
				"observed_bps": egress.BPS,
				"p95_bps":      egress.P95,
				"score":        math.Round(egress.Score*100) / 100,
				"streak":       egress.Streak,
			},
		})
	}
	return out
}

func sortedPorts(set map[int]struct{}, limit int) []int {
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

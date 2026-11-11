package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/yqjwxz/beacon/internal/flow"
	"github.com/yqjwxz/beacon/internal/procfs"
)

// cmdFlow prints one live snapshot of the connection table. History queries
// stay in vmui; this command is for "what is happening on this box right now".
func cmdFlow(args []string) error {
	fs := flag.NewFlagSet("flow", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	top := fs.Int("top", 10, "rows per table")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*path, nil)
	if err != nil {
		return err
	}

	src := procfs.New(cfg.Agent.ProcFS, cfg.Agent.SysFS)
	f, err := os.Open(src.ProcPath("net", "nf_conntrack"))
	if err != nil {
		return fmt.Errorf("open nf_conntrack: %w (the agent needs root)", err)
	}
	defer f.Close()

	entries, total, err := flow.ReadConntrack(f, cfg.Flow.MaxEntries)
	if err != nil {
		return err
	}
	now := time.Now()
	sample := flow.Aggregate(entries, flow.LocalAddresses(), now)

	baseline := flow.LoadBaseline(filepath.Join(cfg.Agent.StateDir, "flow", "baseline.json"))
	_, p95, _, count := baseline.Stats(now)
	findings := flow.Detect(sample, flow.EgressContext{
		P95: p95, Samples: count, MinScore: 3,
	})

	if *asJSON {
		return emitJSON(map[string]any{
			"at": now, "entries_total": total, "sampled": len(entries),
			"sample": sample, "p95_bps": p95, "samples": count, "findings": findings,
		})
	}

	fmt.Printf("conntrack entries: %d (sampled %d of max %d)\n", total, len(entries), cfg.Flow.MaxEntries)
	fmt.Printf("inbound:  %d conns, %d unreplied, %d unique srcs, %d unique dst ports\n",
		sample.In.Conns, sample.In.Unreplied, len(sample.UniqueSrcsIn), len(sample.UniqueDstPortsIn))
	fmt.Printf("outbound: %d conns, %d unreplied, %d unique dst ports\n",
		sample.Out.Conns, sample.Out.Unreplied, len(sample.UniqueDstPortsOut))
	fmt.Printf("local-only (skipped): %d\n", sample.LocalSkipped)
	fmt.Printf("egress P95 for this hour: %.1f KB/s (%d samples)\n", p95/1024, count)

	if ports := sample.TopPorts(*top); len(ports) > 0 {
		fmt.Println("\nbusiest buckets:")
		for _, p := range ports {
			agg := sample.Ports[p.Key]
			fmt.Printf("  %-12s %6d conns (%d unreplied)\n", p.Key, agg.Conns, agg.Unreplied)
		}
	}
	if dsts := sample.TopDestinations(*top); len(dsts) > 0 {
		fmt.Println("\ntop outbound destinations:")
		for _, d := range dsts {
			fmt.Printf("  %-24s %6d\n", d.Dst, d.Conns)
		}
	}
	if in := topInboundPorts(sample, *top); len(in) > 0 {
		fmt.Println("\ninbound destination ports:")
		for _, p := range in {
			fmt.Printf("  %-8s %6d conns\n", strconv.Itoa(p.port), p.conns)
		}
	}

	if len(findings) == 0 {
		fmt.Println("\nfindings: none")
		return nil
	}
	fmt.Println("\nfindings:")
	for _, f := range findings {
		fmt.Printf("  [%s] %-16s score=%.1f\n", f.Severity, f.Kind, f.Score)
	}
	return nil
}

type portCount struct {
	port  int
	conns int
}

// topInboundPorts reconstructs inbound ports from the bucket map. Non-common
// ports are collapsed into "other", so this is the best the bounded model can
// show; the exact list only exists inside the detector.
func topInboundPorts(s *flow.Sample, k int) []portCount {
	var out []portCount
	for key, agg := range s.Ports {
		if len(key) < 3 || key[:2] != "in" {
			continue
		}
		p, err := strconv.Atoi(key[3:])
		if err != nil {
			continue
		}
		out = append(out, portCount{p, agg.Conns})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].conns > out[j].conns })
	if len(out) > k {
		out = out[:k]
	}
	return out
}

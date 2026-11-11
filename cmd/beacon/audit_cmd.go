package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yqjwxz/beacon/internal/audit"
	"github.com/yqjwxz/beacon/internal/config"
)

func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: beacon audit fw|ports|exposure [-config path] [--json]")
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfig(*path, nil)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := audit.ExecRunner{}

	switch args[0] {
	case "fw":
		return auditFW(ctx, cfg, runner, *asJSON)
	case "ports":
		return auditPorts(ctx, cfg, runner, *asJSON)
	case "exposure":
		return auditExposure(ctx, cfg, runner, *asJSON)
	default:
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

func auditFW(ctx context.Context, cfg *config.Config, r audit.Runner, asJSON bool) error {
	snap, active, err := audit.CollectFirewall(ctx, r)
	if err != nil {
		return err
	}
	prev := audit.LoadSnapshotFile(filepath.Join(cfg.Agent.StateDir, "audit", "fw.json"))
	d := audit.Diff{BeforeHash: "", AfterHash: snap.Hash}
	if prev != nil {
		d = audit.DiffSnapshots(prev, snap)
	}

	if asJSON {
		out := map[string]any{
			"backend": snap.Backend, "active": active, "hash": snap.Hash,
			"rules": snap.Rules, "policy": snap.Policy,
			"ipv6_covered":  snap.IPv6Covered,
			"risky_rules":   audit.RiskyRules(snap),
			"open_policies": audit.OpenPolicies(snap),
			"diff":          d,
		}
		return emitJSON(out)
	}

	fmt.Printf("backend:      %s (active=%v)\n", snap.Backend, active)
	fmt.Printf("ruleset hash: %s\n", snap.Hash)
	fmt.Printf("ipv6 covered: %v\n", snap.IPv6Covered)
	counts := snap.CountByTable()
	tables := make([]string, 0, len(counts))
	for t := range counts {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		fmt.Printf("rules[%s]: %d\n", t, counts[t])
	}
	if len(snap.Policy) > 0 {
		fmt.Println("policies:")
		for k, v := range snap.Policy {
			fmt.Printf("  %-30s %s\n", k, v)
		}
	}
	if open := audit.OpenPolicies(snap); len(open) > 0 {
		fmt.Println("OPEN POLICIES (accept by default):")
		for _, o := range open {
			fmt.Printf("  %s\n", o)
		}
	}
	if risky := audit.RiskyRules(snap); len(risky) > 0 {
		fmt.Println("risky rules (dangerous port open to the world):")
		for _, rr := range risky {
			fmt.Printf("  %-8s %-6s %s\n", rr.DPort, rr.Proto, rr.Text)
		}
	}

	if prev != nil {
		if d.Empty() && !d.Flushed {
			fmt.Println("diff: no change since last snapshot")
		} else {
			fmt.Printf("diff: +%d -%d policy=%d flushed=%v\n",
				len(d.Added), len(d.Removed), len(d.PolicyChanges), d.Flushed)
			for _, rr := range d.Added {
				fmt.Printf("  + %s\n", rr.Text)
			}
			for _, rr := range d.Removed {
				fmt.Printf("  - %s\n", rr.Text)
			}
			for _, pc := range d.PolicyChanges {
				fmt.Printf("  ~ %s: %s -> %s\n", pc.Chain, pc.Before, pc.After)
			}
		}
	}
	return nil
}

func auditPorts(ctx context.Context, cfg *config.Config, r audit.Runner, asJSON bool) error {
	listens, err := audit.CollectPorts(ctx, r)
	if err != nil {
		return err
	}
	prev := audit.LoadListensFile(filepath.Join(cfg.Agent.StateDir, "audit", "ports.json"))
	d := audit.DiffListens(prev, listens)

	if asJSON {
		return emitJSON(map[string]any{"listeners": listens, "diff": d})
	}

	fmt.Printf("%-5s %-24s %-8s %-8s %s\n", "PROTO", "ADDR", "PORT", "UID", "PROCESS")
	for _, l := range listens {
		fmt.Printf("%-5s %-24s %-8d %-8d %s\n", l.Proto, l.Addr, l.Port, l.UID, l.Comm)
	}
	if d.Empty() {
		fmt.Println("diff: no change since last snapshot")
		return nil
	}
	for _, l := range d.Added {
		fmt.Printf("+ %s %s:%d %s\n", l.Proto, l.Addr, l.Port, l.Comm)
	}
	for _, l := range d.Removed {
		fmt.Printf("- %s %s:%d %s\n", l.Proto, l.Addr, l.Port, l.Comm)
	}
	for _, w := range d.Widened {
		fmt.Printf("! %s %d moved %s -> %s\n", w.After.Proto, w.After.Port, w.Before.Addr, w.After.Addr)
	}
	return nil
}

func auditExposure(ctx context.Context, cfg *config.Config, r audit.Runner, asJSON bool) error {
	listens, err := audit.CollectPorts(ctx, r)
	if err != nil {
		return err
	}
	reach := audit.ProbePorts(ctx, cfg.Audit.Probe.PublicIP, listens, cfg.Audit.Probe.Timeout.D())

	sg := make([]audit.SGEntry, 0, len(cfg.Audit.SG.Entries))
	for _, e := range cfg.Audit.SG.Entries {
		sg = append(sg, audit.SGEntry{Proto: e.Proto, Port: e.Port, CIDR: e.CIDR})
	}
	exp := audit.Evaluate(audit.ExposureInput{
		Listen:    listens,
		SG:        sg,
		SGKnown:   cfg.Audit.SG.Known,
		Reachable: reach,
		Allow:     audit.NewMatcher(cfg.Audit.PortAllow),
	})

	if asJSON {
		return emitJSON(exp)
	}

	fmt.Printf("public listeners: %d\n", len(exp.PublicListen))
	for _, l := range exp.PublicListen {
		fmt.Printf("  %-5s %-10s %-6d %s\n", l.Proto, l.Addr, l.Port, l.Comm)
	}
	if exp.ProbeUnknown {
		fmt.Println("external reachability: UNKNOWN (set audit.probe.public_ip)")
	} else {
		fmt.Printf("reachable from %s: %d\n", cfg.Audit.Probe.PublicIP, len(exp.Reachable))
	}
	if exp.SGUnknown {
		fmt.Println("security group: UNKNOWN (set audit.security_group.known + entries)")
	} else {
		fmt.Printf("security group allows %d ports with no listener\n", len(exp.SGOpenNoListener))
		for _, e := range exp.SGOpenNoListener {
			fmt.Printf("  %s/%d from %s\n", e.Proto, e.Port, e.CIDR)
		}
	}
	if len(exp.Unexpected) == 0 {
		fmt.Println("UNEXPECTED EXPOSURE: none")
	} else {
		fmt.Println("UNEXPECTED EXPOSURE:")
		for _, l := range exp.Unexpected {
			fmt.Printf("  %s %s:%d %s\n", l.Proto, l.Addr, l.Port, l.Comm)
		}
	}
	return nil
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/yqjwxz/beacon/internal/proctop"
)

func cmdTop(args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	path := fs.String("config", "", "path to YAML config")
	by := fs.String("by", "cpu", "rank by cpu or mem")
	n := fs.Int("n", 10, "rows to show")
	interval := fs.Duration("interval", time.Second, "sampling interval")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *by != "cpu" && *by != "mem" {
		return fmt.Errorf("-by must be cpu or mem")
	}
	cfg, err := loadConfig(*path, nil)
	if err != nil {
		return err
	}

	root := cfg.Agent.ProcFS
	if root == "" {
		root = "/proc"
	}
	before := proctop.Read(root)
	if before == nil {
		return fmt.Errorf("cannot read %s (run as root for full process visibility)", root)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *interval+5*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(*interval):
	}

	after := proctop.Read(root)
	rows := proctop.Top(before, after, *interval, *by, *n)

	if *asJSON {
		return emitJSON(map[string]any{"by": *by, "interval": interval.String(), "rows": rows})
	}

	fmt.Printf("%-8s %8s %10s  %s\n", "PID", "CPU%", "RSS(MB)", "COMMAND")
	for _, r := range rows {
		fmt.Printf("%-8d %8.1f %10.1f  %s\n", r.PID, r.CPU, r.RSSMB, r.Comm)
	}
	return nil
}

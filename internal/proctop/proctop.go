// Package proctop samples per-process CPU and memory from procfs. It is a
// debugging aid for the "what is eating this box" question, not a metric
// pipeline: labels never leave the CLI.
package proctop

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sample is one process observation.
type Sample struct {
	PID  int
	Comm string
	// Ticks is utime+stime in clock ticks, used to compute CPU deltas.
	Ticks uint64
	RSS   uint64 // bytes
}

// clockTicks is USER_HZ, which is 100 on every Linux ABI this agent targets.
const clockTicks = 100

// Read samples every process under root (normally /proc).
func Read(root string) map[int]Sample {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make(map[int]Sample, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, ticks, ok := readStat(filepath.Join(root, e.Name(), "stat"))
		if !ok {
			continue
		}
		out[pid] = Sample{PID: pid, Comm: comm, Ticks: ticks, RSS: readRSS(filepath.Join(root, e.Name(), "statm"))}
	}
	return out
}

// readStat parses the fields that matter from /proc/<pid>/stat. The comm field
// may contain spaces and parentheses, so parsing starts after the last ')'.
func readStat(path string) (comm string, ticks uint64, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open {
		return "", 0, false
	}
	comm = s[open+1 : closeIdx]
	fields := strings.Fields(s[closeIdx+1:])
	// fields[0] is state (field 3); utime is field 14, stime field 15.
	if len(fields) < 13 {
		return comm, 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return comm, 0, false
	}
	return comm, utime + stime, true
}

func readRSS(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

// Row is one line of the ranked output.
type Row struct {
	PID   int     `json:"pid"`
	Comm  string  `json:"comm"`
	CPU   float64 `json:"cpu_percent"`
	RSSMB float64 `json:"rss_mb"`
}

// Top ranks the delta between two samples. by is "cpu" or "mem".
func Top(before, after map[int]Sample, elapsed time.Duration, by string, n int) []Row {
	if elapsed <= 0 {
		elapsed = time.Second
	}
	rows := make([]Row, 0, len(after))
	for pid, cur := range after {
		prev, ok := before[pid]
		if !ok {
			continue
		}
		ticks := cur.Ticks
		if ticks >= prev.Ticks {
			ticks -= prev.Ticks
		} else {
			ticks = 0
		}
		rows = append(rows, Row{
			PID:   pid,
			Comm:  cur.Comm,
			CPU:   float64(ticks) / clockTicks / elapsed.Seconds() * 100,
			RSSMB: float64(cur.RSS) / (1 << 20),
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if by == "mem" {
			return rows[i].RSSMB > rows[j].RSSMB
		}
		if rows[i].CPU != rows[j].CPU {
			return rows[i].CPU > rows[j].CPU
		}
		return rows[i].RSSMB > rows[j].RSSMB
	})
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

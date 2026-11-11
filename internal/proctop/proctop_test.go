package proctop

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func writeProc(t *testing.T, root string, pid int, comm string, utime, stime, rssPages int) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := itoa(pid) + " (" + comm + ") S 1 1 1 0 -1 0 0 0 0 0 " + itoa(utime) + " " + itoa(stime) + " 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	statm := "1000 " + itoa(rssPages) + " 100 1 0 0 0\n"
	if err := os.WriteFile(filepath.Join(dir, "statm"), []byte(statm), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadAndTop(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 100, "nginx worker", 100, 100, 256) // 5MB
	writeProc(t, root, 101, "postgres", 10, 10, 10240)     // 40MB

	before := Read(root)
	if len(before) != 2 {
		t.Fatalf("procs = %d", len(before))
	}
	if before[100].Comm != "nginx worker" {
		t.Fatalf("comm with space = %q", before[100].Comm)
	}

	// postgres burns 100 ticks (1s CPU) over the interval.
	writeProc(t, root, 101, "postgres", 110, 10, 10240)
	after := Read(root)

	cpu := Top(before, after, time.Second, "cpu", 2)
	if len(cpu) != 2 || cpu[0].PID != 101 {
		t.Fatalf("cpu ranking = %+v", cpu)
	}
	if cpu[0].CPU < 99 || cpu[0].CPU > 101 {
		t.Errorf("cpu = %f, want ~100", cpu[0].CPU)
	}

	mem := Top(before, after, time.Second, "mem", 2)
	if mem[0].PID != 101 || mem[0].RSSMB < 39 || mem[0].RSSMB > 41 {
		t.Fatalf("mem ranking = %+v", mem)
	}
}

func TestTopSkipsNewProcesses(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 200, "old", 0, 0, 100)
	before := Read(root)
	writeProc(t, root, 201, "new", 50, 50, 100)
	after := Read(root)

	rows := Top(before, after, time.Second, "cpu", 10)
	if len(rows) != 1 || rows[0].PID != 200 {
		t.Fatalf("rows = %+v", rows)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

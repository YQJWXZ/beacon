package wal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func mustAppend(t *testing.T, w *WAL, s string) {
	t.Helper()
	if _, err := w.Append([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, w *WAL, pos Position) []string {
	t.Helper()
	it := w.Iterator(pos)
	var out []string
	for {
		p, _, err := it.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(p))
	}
}

func TestAppendRead(t *testing.T) {
	w, err := Open(t.TempDir(), 1<<20, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	mustAppend(t, w, "a")
	mustAppend(t, w, "bb")
	mustAppend(t, w, "ccc")

	got := readAll(t, w, Position{})
	want := []string{"a", "bb", "ccc"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReopenPreservesRecords(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 1<<20, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, w, "one")
	mustAppend(t, w, "two")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dir, 1<<20, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	got := readAll(t, w2, Position{})
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("after reopen got %v", got)
	}
}

func TestRotation(t *testing.T) {
	w, err := Open(t.TempDir(), 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 20; i++ {
		mustAppend(t, w, "012345678901234567890123456789")
	}
	if n := len(w.Segments()); n < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", n)
	}
	if got := readAll(t, w, Position{}); len(got) != 20 {
		t.Fatalf("got %d records after rotation", len(got))
	}
}

func TestTornTailIsRepaired(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 1<<20, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, w, "keep-me")
	mustAppend(t, w, "truncate-me")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash mid-write: cut the last record in half.
	files, _ := filepath.Glob(filepath.Join(dir, "*.seg"))
	if len(files) != 1 {
		t.Fatalf("unexpected segments: %v", files)
	}
	info, _ := os.Stat(files[0])
	if err := os.Truncate(files[0], info.Size()-3); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dir, 1<<20, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	got := readAll(t, w2, Position{})
	if len(got) != 1 || got[0] != "keep-me" {
		t.Fatalf("repair kept %v", got)
	}
	// Appending after repair must work and stay readable.
	mustAppend(t, w2, "after-repair")
	if got := readAll(t, w2, Position{}); len(got) != 2 {
		t.Fatalf("post-repair records = %v", got)
	}
}

func TestAckAllowsTruncation(t *testing.T) {
	w, err := Open(t.TempDir(), 300, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	payload := bytes.Repeat([]byte("x"), 40)
	var last Position
	for i := 0; i < 20; i++ {
		p, err := w.Append(payload)
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	if w.Bytes() <= 300 {
		t.Fatalf("expected to exceed budget, bytes=%d", w.Bytes())
	}
	w.SetAck(Position{Seg: last.Seg, Off: 0})
	if w.Bytes() > 300*2 {
		t.Fatalf("segment truncation ineffective: %d bytes", w.Bytes())
	}
}

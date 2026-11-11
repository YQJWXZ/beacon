package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRemovesOldEvents(t *testing.T) {
	store, err := OpenEvents(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now()
	rows := []EventRow{
		{Time: now.Add(-100 * 24 * time.Hour), Host: "h", Type: "old", Severity: "P2"},
		{Time: now.Add(-10 * 24 * time.Hour), Host: "h", Type: "recent", Severity: "P2"},
	}
	if err := store.Insert(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	n, err := store.Prune(context.Background(), now.Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned = %d, want 1", n)
	}

	left, total, err := store.Query(context.Background(), "", "", now.Add(-1000*24*time.Hour), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(left) != 1 || left[0].Type != "recent" {
		t.Fatalf("left = %+v total=%d", left, total)
	}

	if err := store.Vacuum(context.Background()); err != nil {
		t.Fatal(err)
	}
}

package shipper

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/yqjwxz/beacon/internal/promwrite"
	"github.com/yqjwxz/beacon/internal/transport"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func payload(t *testing.T, v float64) []byte {
	t.Helper()
	b, err := promwrite.Marshal([]prompb.TimeSeries{
		promwrite.Gauge("probe", map[string]string{"host": "h"}, v, time.Now().UnixMilli()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestShipperRetainsDataDuringOutage(t *testing.T) {
	var healthy atomic.Bool
	var received atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	tr, err := transport.New(transport.Config{Endpoint: srv.URL + "/api/v1/write", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{Dir: t.TempDir(), MaxBytes: 1 << 20, SegSize: 1 << 16, Batch: 10}, tr, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	for i := 0; i < 3; i++ {
		if err := s.Append(payload(t, float64(i))); err != nil {
			t.Fatal(err)
		}
	}

	// While the center is down the WAL must keep the data.
	waitFor(t, func() bool { return s.BufferBytes() > 0 }, "expected buffered data during outage")
	time.Sleep(150 * time.Millisecond)
	if _, failed, _ := s.Stats(); failed == 0 {
		t.Fatal("expected at least one failed send")
	}
	if s.BufferBytes() == 0 {
		t.Fatal("buffered data was dropped during outage")
	}

	healthy.Store(true)
	waitFor(t, func() bool {
		sent, _, _ := s.Stats()
		return sent > 0 && received.Load() > 0
	}, "shipper did not recover after the center came back")
	waitFor(t, func() bool { return s.BufferBytes() == 0 }, "wal was not drained after recovery")
}

func TestShipperResumesFromAckAfterRestart(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tr, err := transport.New(transport.Config{Endpoint: srv.URL + "/api/v1/write", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	// First process writes but never ships.
	s1, err := New(Options{Dir: dir, MaxBytes: 1 << 20, SegSize: 1 << 16, Batch: 10}, tr, discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Append(payload(t, 42)); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Second process must pick up the backlog.
	s2, err := New(Options{Dir: dir, MaxBytes: 1 << 20, SegSize: 1 << 16, Batch: 10}, tr, discard())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s2.Run(ctx)

	waitFor(t, func() bool { return received.Load() > 0 }, "backlog was not shipped after restart")
	waitFor(t, func() bool { return s2.BufferBytes() == 0 }, "wal not drained")
}

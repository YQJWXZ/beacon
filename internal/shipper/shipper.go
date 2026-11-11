// Package shipper drains the WAL into the center with at-least-once semantics.
// It never drops data because the network is down: failures only slow the drain.
package shipper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yqjwxz/beacon/internal/promwrite"
	"github.com/yqjwxz/beacon/internal/transport"
	"github.com/yqjwxz/beacon/internal/wal"
)

type Options struct {
	Dir      string
	MaxBytes int64
	SegSize  int64
	// Batch is the maximum number of WAL records merged into one request.
	Batch int
}

type Shipper struct {
	wal     *wal.WAL
	tr      transport.Transport
	log     *slog.Logger
	ackPath string
	batch   int
	notify  chan struct{}

	mu      sync.Mutex
	pos     wal.Position
	sent    atomic.Uint64
	failed  atomic.Uint64
	dropped atomic.Uint64
}

type ackFile struct {
	Seg uint64 `json:"seg"`
	Off int64  `json:"off"`
}

func New(opts Options, tr transport.Transport, log *slog.Logger) (*Shipper, error) {
	if opts.Batch <= 0 {
		opts.Batch = 200
	}
	w, err := wal.Open(opts.Dir, opts.MaxBytes, opts.SegSize)
	if err != nil {
		return nil, err
	}
	s := &Shipper{
		wal:     w,
		tr:      tr,
		log:     log,
		ackPath: filepath.Join(opts.Dir, "ack.json"),
		batch:   opts.Batch,
		notify:  make(chan struct{}, 1),
	}
	if a, err := s.loadAck(); err == nil {
		s.pos = a
		w.SetAck(a)
	}
	return s, nil
}

func (s *Shipper) loadAck() (wal.Position, error) {
	b, err := os.ReadFile(s.ackPath)
	if err != nil {
		return wal.Position{}, err
	}
	var a ackFile
	if err := json.Unmarshal(b, &a); err != nil {
		return wal.Position{}, err
	}
	return wal.Position{Seg: a.Seg, Off: a.Off}, nil
}

func (s *Shipper) saveAck(p wal.Position) error {
	b, err := json.Marshal(ackFile{Seg: p.Seg, Off: p.Off})
	if err != nil {
		return err
	}
	tmp := s.ackPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.ackPath)
}

// Append queues one marshaled write request.
func (s *Shipper) Append(payload []byte) error {
	if _, err := s.wal.Append(payload); err != nil {
		return err
	}
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}

// BufferBytes is the WAL size, exposed for self-monitoring.
func (s *Shipper) BufferBytes() int64 { return s.wal.PendingBytes() }

// Stats returns sent and failed request counts.
func (s *Shipper) Stats() (sent, failed, dropped uint64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

func (s *Shipper) Close() error { return s.wal.Close() }

// Run drains the WAL until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.flush(ctx)
		if err != nil {
			s.failed.Add(1)
			s.log.Warn("ship failed", "err", err, "buffered_bytes", s.wal.Bytes(), "retry_in", backoff.String())
			if !sleep(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second

		if n == 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.notify:
			case <-time.After(time.Second):
			}
		}
	}
}

// flush sends at most one merged batch. It returns the number of records sent.
func (s *Shipper) flush(ctx context.Context) (int, error) {
	s.mu.Lock()
	start := s.pos
	s.mu.Unlock()

	it := s.wal.Iterator(start)
	var payloads [][]byte
	var after wal.Position
	var bytes int
	skipped := false
	for len(payloads) < s.batch && bytes < 4<<20 {
		p, next, err := it.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, wal.ErrCorrupt) {
			// Skip the damaged segment rather than stalling forever.
			skipped = true
			s.dropped.Add(1)
			after = it.SkipSegment()
			s.log.Error("corrupt wal segment skipped", "position", after.String())
			continue
		}
		if err != nil {
			return 0, err
		}
		payloads = append(payloads, p)
		after = next
		bytes += len(p)
	}
	if len(payloads) == 0 {
		if skipped {
			s.advance(after)
		}
		return 0, nil
	}

	merged, err := promwrite.Merge(payloads)
	if err != nil {
		return 0, fmt.Errorf("merge batch: %w", err)
	}
	if err := s.tr.Send(ctx, merged); err != nil {
		return 0, err
	}

	s.advance(after)
	s.sent.Add(1)
	return len(payloads), nil
}

func (s *Shipper) advance(p wal.Position) {
	s.mu.Lock()
	s.pos = p
	s.mu.Unlock()
	if err := s.saveAck(p); err != nil {
		s.log.Warn("persist ack failed", "err", err)
	}
	s.wal.SetAck(p)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

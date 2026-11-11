// Package eventlog spools audit events on disk and ships them to the center.
// Events are low volume but high value, so they get their own simple
// append-and-ack file instead of going through the metrics WAL.
package eventlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yqjwxz/beacon/internal/audit"
)

// Log is both an audit.Sink and a background shipper.
type Log struct {
	dir     string
	baseURL string
	token   string
	host    string
	http    *http.Client

	mu  sync.Mutex
	off int64
}

func New(dir, baseURL, token, host string) (*Log, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("eventlog: empty center URL")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Log{
		dir: dir, baseURL: strings.TrimRight(baseURL, "/"), token: token, host: host,
		http: &http.Client{Timeout: 10 * time.Second},
	}
	if b, err := os.ReadFile(l.offPath()); err == nil {
		l.off, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	l.compact()
	return l, nil
}

func (l *Log) path() string    { return filepath.Join(l.dir, "events.jsonl") }
func (l *Log) offPath() string { return filepath.Join(l.dir, "offset") }

// Emit appends one event. Failures are intentionally silent: audit must never
// break collection, and the next refresh will re-report state changes.
func (l *Log) Emit(e audit.Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(b)
	_ = f.Close()
}

// Run ships pending events every few seconds.
func (l *Log) Run(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = l.flush(ctx)
		}
	}
}

func (l *Log) flush(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	st, err := os.Stat(l.path())
	if err != nil {
		return nil
	}
	if st.Size() <= l.off {
		return nil
	}

	f, err := os.Open(l.path())
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(l.off, io.SeekStart); err != nil {
		return err
	}
	buf, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return err
	}
	// Only consume complete lines; a partial write stays for next time.
	idx := bytes.LastIndexByte(buf, '\n')
	if idx < 0 {
		return nil
	}
	consumed := int64(idx + 1)

	var events []audit.Event
	for _, line := range bytes.Split(buf[:idx], []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(line, &e); err == nil {
			events = append(events, e)
		}
	}
	if len(events) == 0 {
		l.advance(consumed)
		return nil
	}
	if err := l.post(ctx, events); err != nil {
		return err
	}
	l.advance(consumed)
	return nil
}

func (l *Log) post(ctx context.Context, events []audit.Event) error {
	body, err := json.Marshal(map[string]any{"host": l.host, "events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.token)

	resp, err := l.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("events rejected: status %d", resp.StatusCode)
	}
	return nil
}

func (l *Log) advance(n int64) {
	l.off += n
	tmp := l.offPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(l.off, 10)), 0o600); err == nil {
		_ = os.Rename(tmp, l.offPath())
	}
	l.compact()
}

// compact rewrites the spool once everything has been shipped and it has grown
// large enough to be worth the truncation.
func (l *Log) compact() {
	if l.off < 4<<20 {
		return
	}
	st, err := os.Stat(l.path())
	if err != nil || st.Size() != l.off {
		return
	}
	if err := os.Truncate(l.path(), 0); err == nil {
		l.off = 0
		_ = os.WriteFile(l.offPath(), []byte("0"), 0o600)
	}
}

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// EventStore keeps audit events in SQLite. Events are append-only and queried
// by host and time; there is no update path by design.
type EventStore struct {
	db *sql.DB
}

type EventRow struct {
	Time     time.Time       `json:"time"`
	Host     string          `json:"host"`
	Type     string          `json:"type"`
	Severity string          `json:"severity"`
	Data     json.RawMessage `json:"data"`
}

func OpenEvents(path string) (*EventStore, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS events (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  host     TEXT NOT NULL,
  type     TEXT NOT NULL,
  severity TEXT NOT NULL,
  data     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type, ts);
`); err != nil {
		db.Close()
		return nil, fmt.Errorf("init events db: %w", err)
	}
	return &EventStore{db: db}, nil
}

func (s *EventStore) Close() error { return s.db.Close() }

// Insert writes a batch in one transaction.
func (s *EventStore) Insert(ctx context.Context, events []EventRow) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events (ts, host, type, severity, data) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, e.Time.UnixMilli(), e.Host, e.Type, e.Severity, string(e.Data)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Query returns events newest first.
func (s *EventStore) Query(ctx context.Context, host, typ string, since time.Time, limit int) ([]EventRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT ts, host, type, severity, data FROM events WHERE ts >= ?`
	args := []any{since.UnixMilli()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	if typ != "" {
		q += ` AND type = ?`
		args = append(args, typ)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]EventRow, 0, limit)
	for rows.Next() {
		var ts int64
		var e EventRow
		var data string
		if err := rows.Scan(&ts, &e.Host, &e.Type, &e.Severity, &data); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts).UTC()
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}

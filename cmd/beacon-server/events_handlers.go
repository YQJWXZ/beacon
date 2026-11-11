package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/yqjwxz/beacon/internal/audit"
)

type eventsPayload struct {
	Host   string        `json:"host"`
	Events []audit.Event `json:"events"`
}

// handleEventPost accepts audit events from an authenticated host. The host
// field must match the token, so one machine cannot forge another's audit log.
func (s *Server) handleEventPost(w http.ResponseWriter, r *http.Request) {
	host, ok := s.authenticate(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	var payload eventsPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if payload.Host != "" && payload.Host != host.Name {
		writeError(w, http.StatusForbidden, "host does not match token")
		return
	}
	if len(payload.Events) > 500 {
		writeError(w, http.StatusRequestEntityTooLarge, "too many events per request")
		return
	}

	rows := make([]EventRow, 0, len(payload.Events))
	for _, e := range payload.Events {
		if e.Time.IsZero() {
			e.Time = time.Now()
		}
		if e.Type == "" {
			continue
		}
		data, err := json.Marshal(e.Data)
		if err != nil {
			continue
		}
		rows = append(rows, EventRow{
			Time:     e.Time.UTC(),
			Host:     host.Name,
			Type:     e.Type,
			Severity: e.Severity,
			Data:     data,
		})
	}
	if err := s.events.Insert(r.Context(), rows); err != nil {
		s.log.Error("insert events", "err", err)
		writeError(w, http.StatusInternalServerError, "store failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleEventQuery is admin-only: it uses the enrollment token.
func (s *Server) handleEventQuery(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	q := r.URL.Query()
	since := time.Now().Add(-24 * time.Hour)
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		} else if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = time.Unix(sec, 0)
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 20
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}

	rows, total, err := s.events.Query(r.Context(), q.Get("host"), q.Get("type"), since, limit, offset)
	if err != nil {
		s.log.Error("query events", "err", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": rows, "count": len(rows), "total": total,
		"limit": limit, "offset": offset,
	})
}

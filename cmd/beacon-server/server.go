package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/prometheus/prompb"

	"github.com/yqjwxz/beacon/internal/notify"
	"github.com/yqjwxz/beacon/internal/promwrite"
	"github.com/yqjwxz/beacon/internal/webui"
)

type Server struct {
	store       *Store
	events      *EventStore
	notifier    *notify.Notifier
	vmURL       string
	vmBase      string
	webDir      string
	enrollToken string
	amURL       string
	snoozeKey   []byte
	log         *slog.Logger
	client      *http.Client
}

// ServerOptions groups the wiring needed by the HTTP layer.
type ServerOptions struct {
	VMURL       string
	VMBase      string
	EnrollToken string
	AMURL       string
	Notifier    *notify.Notifier
	SnoozeKey   []byte
	WebDir      string
}

func NewServer(store *Store, events *EventStore, opts ServerOptions, log *slog.Logger) *Server {
	return &Server{
		store:       store,
		events:      events,
		notifier:    opts.Notifier,
		vmURL:       opts.VMURL,
		vmBase:      strings.TrimRight(opts.VMBase, "/"),
		webDir:      opts.WebDir,
		enrollToken: opts.EnrollToken,
		amURL:       opts.AMURL,
		snoozeKey:   opts.SnoozeKey,
		log:         log,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/v1/write", s.handleWrite)
	mux.HandleFunc("POST /api/v1/events", s.handleEventPost)
	mux.HandleFunc("GET /api/v1/events", s.handleEventQuery)
	mux.HandleFunc("GET /api/v1/hosts", s.handleHosts)
	mux.HandleFunc("POST /hooks/alert", s.handleAlert)
	mux.HandleFunc("GET /snooze", s.handleSnooze)
	mux.HandleFunc("GET /api/v1/query", s.handleQuery)
	mux.HandleFunc("GET /api/v1/query_range", s.handleQueryRange)
	mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("POST /api/v1/silences", s.handleSilenceCreate)
	mux.Handle("/", webui.Handler(s.webDir))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

type enrollRequest struct {
	Token    string `json:"token"`
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

type enrollResponse struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Token string `json:"token"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if s.enrollToken == "" {
		writeError(w, http.StatusForbidden, "enrollment disabled: no enroll token configured")
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.enrollToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid enroll token")
		return
	}
	name := req.Host
	if name == "" {
		name = req.Hostname
	}
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing host")
		return
	}

	token, host, err := s.store.Enroll(name)
	if err != nil {
		s.log.Error("enroll failed", "err", err)
		writeError(w, http.StatusInternalServerError, "enroll failed")
		return
	}
	s.log.Info("host enrolled", "host", host.Name, "id", host.ID, "version", req.Version)
	writeJSON(w, http.StatusOK, enrollResponse{ID: host.ID, Host: host.Name, Token: token})
}

func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request) {
	host, ok := s.authenticate(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body failed")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty body")
		return
	}
	// Reject series that claim another host's identity: one compromised agent
	// must not be able to poison another host's data.
	wr, err := promwrite.Decode(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	for _, ts := range wr.Timeseries {
		if hostLabel(ts) != host.Name {
			writeError(w, http.StatusForbidden, "host label does not match token")
			return
		}
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.vmURL, bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build upstream request failed")
		return
	}
	for _, h := range []string{"Content-Type", "Content-Encoding", "X-Prometheus-Remote-Write-Version"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("upstream write failed", "host", host.Name, "err", err)
		writeError(w, http.StatusBadGateway, "upstream unavailable")
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode/100 == 2 {
		s.store.Touch(host.ID)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}
	s.log.Warn("upstream rejected write", "host", host.Name, "status", resp.StatusCode, "body", string(respBody))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	// The enroll token doubles as the admin token in M1.
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	hosts := s.store.List()
	type item struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Created  time.Time `json:"created_at"`
		LastSeen time.Time `json:"last_seen"`
	}
	out := make([]item, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, item{ID: h.ID, Name: h.Name, Created: h.CreatedAt, LastSeen: h.LastSeen})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

func (s *Server) authenticate(r *http.Request) (*Host, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return nil, false
	}
	return s.store.Verify(h[len(prefix):])
}

// isAdmin checks the enrollment token, which doubles as the admin credential.
func (s *Server) isAdmin(r *http.Request) bool {
	if s.enrollToken == "" {
		return false
	}
	got := r.Header.Get("Authorization")
	want := "Bearer " + s.enrollToken
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// hostLabel returns the value of the host label, or "" when absent.
func hostLabel(ts prompb.TimeSeries) string {
	for _, l := range ts.Labels {
		if l.Name == "host" {
			return l.Value
		}
	}
	return ""
}
